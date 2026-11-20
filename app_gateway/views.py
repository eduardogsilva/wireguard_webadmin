from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import F, ProtectedError
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.formats import date_format
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.timezone import localtime
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from app_gateway.caddy_config_export import (
    ACME_CERTIFICATE_TYPES, CADDY_EXPORT_DIR, apply_caddy_config, auto_apply_caddy_config, caddy_export_pending,
    load_exported_files, load_worker_export
)
from app_gateway.certificate_status import inspect_certificate
from app_gateway.forms import (
    ApplicationForm, ApplicationHostForm, AccessPolicyForm,
    ApplicationPolicyForm, ApplicationRouteForm, DnsChallengeCredentialForm
)
from app_gateway.models import (
    Application, ApplicationHost, AccessPolicy, ApplicationPolicy, ApplicationRoute, DnsChallengeCredential,
    RESERVED_APP_NAME
)
from app_gateway.setup_defaults import create_default_entries
from cluster.models import ClusterSettings, Worker
from user_manager.models import UserAcl


@login_required
def view_app_gateway_list(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=20).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    create_default_entries()
    applications = Application.objects.all().order_by('name')
    hosts = ApplicationHost.objects.all().order_by('hostname')
    access_policies = AccessPolicy.objects.all().order_by('name')
    app_policies = ApplicationPolicy.objects.all().order_by('application__name')
    dns_credentials = DnsChallengeCredential.objects.all().order_by('name')

    tab = request.GET.get('tab', 'applications')

    context = {
        'applications': applications,
        'hosts': hosts,
        'access_policies': access_policies,
        'app_policies': app_policies,
        'dns_credentials': dns_credentials,
        'active_tab': tab,
        'caddy_enabled': settings.CADDY_ENABLED,
        'pending_export': caddy_export_pending(),
    }
    return render(request, 'app_gateway/app_gateway_list.html', context)


@login_required
def view_application_details(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=20).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_uuid = request.GET.get('uuid')
    application = get_object_or_404(Application, uuid=application_uuid)

    hosts = application.hosts.all().order_by('hostname')
    routes = application.routes.all().order_by('order', 'path_prefix')

    is_reserved = application.name == RESERVED_APP_NAME

    context = {
        'application': application,
        'hosts': hosts,
        'routes': routes,
        'is_reserved': is_reserved,
        'caddy_enabled': settings.CADDY_ENABLED,
        'pending_export': caddy_export_pending(),
        'page_title': _('Application Details'),
    }
    return render(request, 'app_gateway/application_details.html', context)


def worker_runs_gateway(worker):
    # Workers running the App Gateway report the Caddy service; VPN-only workers do not serve applications
    worker_status = getattr(worker, 'workerstatus', None)
    return bool(worker_status and 'caddy' in (worker_status.services_status or {}))


def describe_certificate_status(certificate, certificate_type):
    """Badge information for a certificate inspected on the primary server or reported by a cluster worker."""
    expiration = ''
    if certificate.get('not_after'):
        not_after = certificate['not_after']
        if isinstance(not_after, str):
            not_after = parse_datetime(not_after)
        if not_after:
            expiration = _('expires %(date)s') % {'date': date_format(localtime(not_after), 'SHORT_DATETIME_FORMAT')}

    if certificate.get('status') == 'trusted':
        return 'success', _('Trusted'), f"{certificate.get('issuer', '')}, {expiration}"
    if certificate.get('status') == 'untrusted' and certificate_type == 'self_signed':
        return 'secondary', _('Self-signed'), expiration
    if certificate.get('status') == 'untrusted':
        detail = _('The trusted certificate could not be issued yet, %(expiration)s') % {'expiration': expiration}
        return 'warning', _('Using fallback'), detail
    if certificate.get('status') == 'unknown':
        return 'light', _('Unknown'), _('No recent report from this server.')
    if certificate.get('status') == 'pending_export':
        return 'info', _('Pending export'), _('Export the configuration to publish this host on this server.')
    return 'danger', _('Unavailable'), _('No certificate is being served for this hostname.')


@login_required
def view_application_certificate_status(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=20).exists():
        return JsonResponse({'error': _('Access Denied')}, status=403)

    application = get_object_or_404(Application, uuid=request.GET.get('uuid'))
    if not settings.CADDY_ENABLED:
        return JsonResponse({'caddy_enabled': False, 'hosts': {}})

    workers = []
    if application.name != RESERVED_APP_NAME and ClusterSettings.objects.filter(name='cluster_settings', enabled=True).exists():
        workers = [
            worker for worker in Worker.objects.filter(enabled=True).select_related('workerstatus').order_by('name')
            if application.is_served_by(worker) and worker_runs_gateway(worker)
        ]
    report_limit = timezone.now() - timedelta(minutes=10)

    # Servers only publish what was exported, so hosts missing from their exported files are pending
    primary_export = load_exported_files(CADDY_EXPORT_DIR) or {}
    primary_exported_hosts = primary_export.get('tls.json', {}).get('hosts', {})
    worker_exported_hosts = {}
    for worker in workers:
        worker_export = load_worker_export(worker) or {}
        worker_exported_hosts[worker.pk] = worker_export.get('tls.json', {}).get('hosts', {})

    hosts_status = {}
    for application_host in application.hosts.all():
        hostname = application_host.hostname.lower()
        servers = []
        # The primary server also manages ACME certificates of applications only served by workers
        primary_handles_host = application.is_served_by(None) or (
            application_host.certificate_type in ACME_CERTIFICATE_TYPES and application.served_by_workers
        )
        if primary_handles_host:
            if hostname in primary_exported_hosts:
                certificate = inspect_certificate(application_host.hostname)
            else:
                certificate = {'status': 'pending_export'}
            servers.append((_('Primary Server'), certificate))

        for worker in workers:
            worker_status = getattr(worker, 'workerstatus', None)
            if hostname not in worker_exported_hosts[worker.pk]:
                certificate = {'status': 'pending_export'}
            elif worker_status and worker_status.certificate_status_updated and worker_status.certificate_status_updated > report_limit:
                certificate = worker_status.certificate_status.get(hostname, {'status': 'unavailable'})
            else:
                certificate = {'status': 'unknown'}
            servers.append((worker.display_name, certificate))

        hosts_status[str(application_host.uuid)] = []
        for server_name, certificate in servers:
            css_class, label, detail = describe_certificate_status(certificate, application_host.certificate_type)
            hosts_status[str(application_host.uuid)].append({
                'server': server_name if workers else '', 'css_class': css_class, 'label': label, 'detail': detail,
            })

    return JsonResponse({'caddy_enabled': True, 'hosts': hosts_status})


@login_required
def view_manage_application(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_uuid = request.GET.get('uuid')

    if application_uuid:
        application = get_object_or_404(Application, uuid=application_uuid)
        if application.name == RESERVED_APP_NAME:
            messages.error(request, _('The WireGuard WebAdmin application cannot be modified.'))
            return redirect(reverse('view_application') + f'?uuid={application.uuid}')
        title = _('Edit Application')
    else:
        application = None
        title = _('Create Application')

    if application:
        cancel_url = reverse('view_application') + f'?uuid={application.uuid}'
    else:
        cancel_url = reverse('app_gateway_list') + '?tab=applications'

    form = ApplicationForm(request.POST or None, instance=application, cancel_url=cancel_url)
    if form.is_valid():
        application = form.save()
        messages.success(request, _('Application saved successfully.'))
        auto_apply_caddy_config(request)
        return redirect(reverse('view_application') + f'?uuid={application.uuid}')

    form_description = {
        'size': 'col-lg-6',
        'content': _('''
        <h5>Application</h5>
        <p>Define the main details of the application you want to expose through the gateway.</p>
        <ul>
            <li><strong>Name</strong>: A unique internal identifier for this application (e.g., "wiki", "crm"). Contains only letters, numbers, hyphens, or underscores.</li>
            <li><strong>Display Name</strong>: A friendly, human-readable name for display purposes.</li>
            <li><strong>Upstream</strong>: The destination URL where requests will be forwarded (e.g., <code>http://10.188.18.27:3000</code>). Must start with <code>http://</code> or <code>https://</code>.</li>
        </ul>
        ''')
    }

    context = {
        'form': form,
        'title': title,
        'page_title': title,
        'form_description': form_description,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_application(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application = get_object_or_404(Application, uuid=request.GET.get('uuid'))

    cancel_url = reverse('app_gateway_list') + '?tab=applications'

    if application.name == RESERVED_APP_NAME:
        messages.error(request, _('The WireGuard WebAdmin application cannot be deleted.'))
        return redirect(reverse('view_application') + f'?uuid={application.uuid}')

    if request.method == 'POST':
        application.delete()
        messages.success(request, _('Application deleted successfully.'))
        auto_apply_caddy_config(request)
        return redirect(cancel_url)

    context = {
        'application': application,
        'title': _('Delete Application'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the application "%(name)s"?') % {'name': application.display_name}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_application_host(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_host_uuid = request.GET.get('uuid')
    application_uuid = request.GET.get('application_uuid')

    if application_host_uuid:
        application_host = get_object_or_404(ApplicationHost, uuid=application_host_uuid)
        application = application_host.application
        title = _('Edit Application Host')
    else:
        application_host = None
        application = get_object_or_404(Application, uuid=application_uuid)
        title = _('Add Application Host')

    cancel_url = reverse('view_application') + f'?uuid={application.uuid}#hosts'

    is_reserved = application.name == RESERVED_APP_NAME
    if is_reserved and not application_host:
        messages.error(request, _('The WireGuard WebAdmin application cannot be modified.'))
        return redirect(cancel_url)

    form = ApplicationHostForm(
        request.POST or None, instance=application_host, cancel_url=cancel_url, is_reserved=is_reserved,
        application=application,
    )
    if form.is_valid():
        host = form.save(commit=False)
        host.application = application
        host.save()
        messages.success(request, _('Application Host saved successfully.'))
        auto_apply_caddy_config(request)
        return redirect(cancel_url)

    form_description_content = _('''
    <h5>Certificate</h5>
    <p>Defines how the TLS certificate for this hostname is issued.</p>
    <ul>
        <li><strong>Trusted certificate (HTTP validation)</strong>: Issued through ACME (e.g. Let's Encrypt) and validated over HTTP. The hostname must point to this server and ports 80/443 must be reachable from the internet.</li>
        <li><strong>Trusted certificate (DNS validation)</strong>: Issued through ACME and validated with a DNS record created using the selected DNS credential. The server does not need to be reachable from the internet.</li>
        <li><strong>Self-signed certificate</strong>: Issued by the internal Caddy CA. Browsers will show a security warning.</li>
    </ul>
    <p>When the fallback option is enabled and a trusted certificate cannot be issued, a self-signed certificate is used until the next successful attempt. Without the fallback, the connection fails until the certificate is issued.</p>
    <p>Use <strong>Retry certificate</strong> in the host list to request a new attempt right away, for example after fixing the DNS or firewall.</p>
    <p><strong>Important:</strong> the certificate is requested as soon as the configuration is applied. With HTTP validation, the hostname must already point to this server: failed attempts count towards the Let's Encrypt limit (5 per hour per hostname). If the DNS is not ready yet, use DNS validation.</p>
    ''')
    if is_reserved:
        form_description_content += _('''
        <div class="alert alert-warning">
            This hostname is used to access WireGuard WebAdmin. If the certificate cannot be issued,
            your browser will show a security warning until the problem is fixed.
        </div>
        ''')

    context = {
        'form': form,
        'title': title,
        'page_title': title,
        'form_description': {'size': 'col-lg-6', 'content': form_description_content},
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_application_host(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_host = get_object_or_404(ApplicationHost, uuid=request.GET.get('uuid'))
    application = application_host.application

    cancel_url = reverse('view_application') + f'?uuid={application.uuid}#hosts'

    if application.name == RESERVED_APP_NAME:
        messages.error(request, _('The WireGuard WebAdmin application cannot be modified.'))
        return redirect(cancel_url)

    if request.method == 'POST':
        application_host.delete()
        messages.success(request, _('Application Host deleted successfully.'))
        auto_apply_caddy_config(request)
        return redirect(cancel_url)

    context = {
        'application_host': application_host,
        'title': _('Delete Application Host'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the host "%(hostname)s"?') % {'hostname': application_host.hostname}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_select_policy_type(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    context = {
        'page_title': _('Select Access Policy Type'),
    }
    return render(request, 'app_gateway/access_policy_type_select.html', context)


@login_required
def view_manage_access_policy(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    access_policy_uuid = request.GET.get('uuid')
    policy_type = request.GET.get('policy_type')

    if access_policy_uuid:
        access_policy = get_object_or_404(AccessPolicy, uuid=access_policy_uuid)
        title = _('Edit Access Policy')
        policy_type = access_policy.policy_type
    else:
        access_policy = None
        title = _('Create Access Policy')

    cancel_url = reverse('app_gateway_list') + '?tab=policies'

    form = AccessPolicyForm(request.POST or None, instance=access_policy, cancel_url=cancel_url, policy_type=policy_type)
    if form.is_valid():
        form.save()
        messages.success(request, _('Access Policy saved successfully.'))
        auto_apply_caddy_config(request)
        return redirect(cancel_url)

    if policy_type == 'public':
        form_description = {
            'size': 'col-lg-6',
            'content': _('''
            <h5>Public Policy</h5>
            <p>A Public policy allows access to the application without requiring any authentication.</p>
            ''')
        }
    elif policy_type == 'deny':
        form_description = {
            'size': 'col-lg-6',
            'content': _('''
            <h5>Deny Policy</h5>
            <p>A Deny policy blocks all access to the matched routes.</p>
            ''')
        }
    else:
        form_description = {
            'size': 'col-lg-6',
            'content': _('''
            <h5>Protected Policy</h5>
            <p>A Protected policy requires users to authenticate before accessing the application.</p>
            <ul>
                <li><strong>Allowed Groups</strong>: Limits access to specific user groups. Note: Using groups requires selecting an Authentication Method of type "Local Password".</li>
                <li><strong>Authentication Methods</strong>: Specify which methods users can use to authenticate (e.g., Local Password, TOTP, OIDC).</li>
            </ul>
            ''')
        }

    context = {
        'form': form,
        'title': title,
        'page_title': title,
        'form_description': form_description,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_access_policy(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    access_policy = get_object_or_404(AccessPolicy, uuid=request.GET.get('uuid'))

    cancel_url = reverse('app_gateway_list') + '?tab=policies'

    if request.method == 'POST':
        try:
            access_policy.delete()
            messages.success(request, _('Access Policy deleted successfully.'))
            auto_apply_caddy_config(request)
        except ProtectedError:
            messages.error(request, _('Cannot delete this Access Policy because it is currently in use by an Application Route or Application Default Policy.'))
        return redirect(cancel_url)

    context = {
        'access_policy': access_policy,
        'title': _('Delete Access Policy'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the access policy "%(name)s"?') % {'name': access_policy.name}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_application_policy(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_policy_uuid = request.GET.get('uuid')
    application_uuid = request.GET.get('application_uuid')

    if application_policy_uuid:
        application_policy = get_object_or_404(ApplicationPolicy, uuid=application_policy_uuid)
        application = application_policy.application
        title = _('Edit Application Default Policy')
    else:
        application_policy = None
        application = get_object_or_404(Application, uuid=application_uuid)
        title = _('Set Application Default Policy')

    cancel_url = reverse('view_application') + f'?uuid={application.uuid}'

    form = ApplicationPolicyForm(request.POST or None, instance=application_policy, cancel_url=cancel_url)
    if form.is_valid():
        policy_config = form.save(commit=False)
        policy_config.application = application
        policy_config.save()
        messages.success(request, _('Application Default Policy saved successfully.'))
        auto_apply_caddy_config(request)
        return redirect(cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_application_policy(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_policy = get_object_or_404(ApplicationPolicy, uuid=request.GET.get('uuid'))
    application = application_policy.application

    cancel_url = reverse('view_application') + f'?uuid={application.uuid}'

    if request.method == 'POST':
        application_policy.delete()
        messages.success(request, _('Application Default Policy deleted successfully.'))
        auto_apply_caddy_config(request)
        return redirect(cancel_url)

    context = {
        'application_policy': application_policy,
        'title': _('Delete Application Default Policy'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to remove the default policy for "%(name)s"?') % {
            'name': application_policy.application.display_name
        }
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_application_route(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_route_uuid = request.GET.get('uuid')
    application_uuid = request.GET.get('application_uuid')

    if application_route_uuid:
        application_route = get_object_or_404(ApplicationRoute, uuid=application_route_uuid)
        application = application_route.application
        title = _('Edit Application Route')
    else:
        application_route = None
        application = get_object_or_404(Application, uuid=application_uuid)
        title = _('Add Application Route')

    cancel_url = reverse('view_application') + f'?uuid={application.uuid}#routes'

    form = ApplicationRouteForm(request.POST or None, instance=application_route, cancel_url=cancel_url)
    if form.is_valid():
        route = form.save(commit=False)
        route.application = application
        route.save()
        messages.success(request, _('Application Route saved successfully.'))
        auto_apply_caddy_config(request)
        return redirect(cancel_url)

    form_description = {
        'size': 'col-lg-6',
        'content': _('''
        <h5>Application Route</h5>
        <p>A Route defines a path prefix within this Application that requires a specific Access Policy.</p>
        <ul>
            <li><strong>Route Name</strong>: An internal identifier for this route (e.g., "public_api", "admin_area"). Used for reference and exports.</li>
            <li><strong>Path Prefix</strong>: The URL path that triggers this route (e.g., <code>/api/</code> or <code>/admin/</code>). Use <code>/</code> to match all remaining paths.</li>
            <li><strong>Policy</strong>: The Access Policy that will be enforced when a user accesses this path.</li>
            <li><strong>Order</strong>: Determines the priority of this route when evaluating the request. Lower numbers are evaluated first. If multiple routes match a path, the one with the lowest order wins.</li>
        </ul>
        ''')
    }

    context = {
        'form': form,
        'title': title,
        'page_title': title,
        'form_description': form_description,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_application_route(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_route = get_object_or_404(ApplicationRoute, uuid=request.GET.get('uuid'))
    application = application_route.application

    cancel_url = reverse('view_application') + f'?uuid={application.uuid}#routes'

    if request.method == 'POST':
        application_route.delete()
        messages.success(request, _('Application Route deleted successfully.'))
        auto_apply_caddy_config(request)
        return redirect(cancel_url)

    context = {
        'application_route': application_route,
        'title': _('Delete Application Route'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the route "%(name)s" (%(path)s)?') % {
            'name': application_route.name,
            'path': application_route.path_prefix
        }
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
@require_POST
def view_retry_application_host_certificate(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_host = get_object_or_404(ApplicationHost, uuid=request.GET.get('uuid'))
    redirect_url = reverse('view_application') + f'?uuid={application_host.application.uuid}#hosts'

    if application_host.certificate_type == 'self_signed':
        messages.error(request, _('This host uses a self-signed certificate.'))
        return redirect(redirect_url)

    if not settings.CADDY_ENABLED:
        messages.error(request, _('This action is not available because Caddy is not enabled.'))
        return redirect(redirect_url)

    ApplicationHost.objects.filter(pk=application_host.pk).update(certificate_generation=F('certificate_generation') + 1)
    apply_caddy_config()

    messages.success(request, _(
        'A new certificate will be requested for %(hostname)s. The current configuration was exported.'
    ) % {'hostname': application_host.hostname})
    return redirect(redirect_url)


@login_required
def view_manage_dns_credential(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    dns_credential_uuid = request.GET.get('uuid')

    if dns_credential_uuid:
        dns_credential = get_object_or_404(DnsChallengeCredential, uuid=dns_credential_uuid)
        title = _('Edit DNS Credential')
    else:
        dns_credential = None
        title = _('Add DNS Credential')

    cancel_url = reverse('app_gateway_list') + '?tab=dns_credentials'

    form = DnsChallengeCredentialForm(request.POST or None, instance=dns_credential, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('DNS Credential saved successfully.'))
        auto_apply_caddy_config(request)
        return redirect(cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
    }
    return render(request, 'app_gateway/dns_credential_form.html', context)


@login_required
def view_delete_dns_credential(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    dns_credential = get_object_or_404(DnsChallengeCredential, uuid=request.GET.get('uuid'))

    cancel_url = reverse('app_gateway_list') + '?tab=dns_credentials'

    if request.method == 'POST':
        try:
            dns_credential.delete()
            messages.success(request, _('DNS Credential deleted successfully.'))
            auto_apply_caddy_config(request)
        except ProtectedError:
            messages.error(request, _('Cannot delete this DNS Credential because it is currently in use by an Application Host.'))
        return redirect(cancel_url)

    context = {
        'dns_credential': dns_credential,
        'title': _('Delete DNS Credential'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the DNS credential "%(name)s"?') % {'name': dns_credential.display_name}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
@require_POST
def view_export_caddy_config(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    redirect_url = reverse('app_gateway_list') + '?tab=applications'
    next_url = request.POST.get('next', '')
    if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        redirect_url = next_url

    if not settings.CADDY_ENABLED:
        messages.error(request, _(
            'Configuration export is not available because Caddy is not enabled. '
            'To use App Gateway and Gatekeeper, start the application using docker-compose-caddy.yml.'
        ))
        return redirect(redirect_url)

    apply_caddy_config()
    messages.success(request, _('Configuration exported successfully.'))
    return redirect(redirect_url)
