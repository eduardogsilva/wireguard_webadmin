from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import ProtectedError
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext_lazy as _

from api.models import WireguardStatusCache
from app_gateway.setup_defaults import get_webadmin_hostnames
from user_manager.models import UserAcl
from wireguard.models import WireGuardInstance
from wireguard_tools.views import export_firewall_configuration, export_wireguard_configuration
from .forms import WorkerForm, ClusterSettingsForm
from .models import ClusterSettings, Worker, WorkerStatus
from .sync import SECTION_NAMES, get_worker_sync_state, get_worker_warnings


def get_worker_status(worker):
    try:
        return worker.workerstatus
    except WorkerStatus.DoesNotExist:
        return None


def describe_worker(worker):
    """Attach the synchronization state, warnings and reported data used by the cluster templates."""
    worker.sync_state = get_worker_sync_state(worker)
    worker.unsynced_sections = [
        section_name for section_name, section in worker.sync_state['sections'].items() if section['state'] != 'synced'
    ]
    worker.error_messages = [
        f"{section_name}: {section['message']}" for section_name, section in worker.sync_state['sections'].items()
        if section['state'] == 'error' and section['message']
    ]
    worker.warnings = get_worker_warnings(worker)
    # Reported data of disabled, refused or offline workers is only the last known state
    worker.operational = worker.enabled and not worker.error_status and worker.is_online
    worker_status = get_worker_status(worker)
    worker.status = worker_status
    worker.services = sorted((worker_status.services_status or {}).items()) if worker_status else []
    worker.runs_gateway = any(service == 'caddy' for service, state in worker.services)
    worker.outdated = bool(worker_status and worker_status.worker_version != settings.CLUSTER_WORKER_CURRENT_VERSION)
    # WireGuard instances that run only on this worker (distributed cluster mode)
    worker.hosted_instances = (
        list(worker.wireguard_instances.order_by('instance_id')) if ClusterSettings.is_distributed() else []
    )
    return worker


@login_required
def cluster_main(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    cluster_settings, cluster_settings_created = ClusterSettings.objects.get_or_create(name='cluster_settings')
    workers = [describe_worker(worker) for worker in Worker.objects.all().select_related('workerstatus').order_by('name')]
    enabled_workers = [worker for worker in workers if worker.enabled]

    master_cache_times = ", ".join(
        str(cache.processing_time_ms) for cache in WireguardStatusCache.objects.filter(cache_type='master').order_by('-created')
    )
    cluster_cache_times = ", ".join(
        str(cache.processing_time_ms) for cache in WireguardStatusCache.objects.filter(cache_type='cluster').order_by('-created')
    )

    context = {
        'page_title': _('Cluster'),
        'workers': workers,
        'cluster_settings': cluster_settings,
        'current_worker_version': settings.CLUSTER_WORKER_CURRENT_VERSION,
        'distributed': ClusterSettings.is_distributed(),
        'primary_instances': WireGuardInstance.objects.filter(worker__isnull=True).order_by('instance_id'),
        # Instances that no server runs: their worker is disabled
        'stopped_instances': [
            instance for worker in workers if not worker.enabled for instance in worker.hosted_instances
        ],
        'summary': {
            'enabled': len(enabled_workers),
            'online': sum(1 for worker in enabled_workers if worker.operational),
            'synced': sum(1 for worker in enabled_workers if worker.operational and worker.sync_state['state'] == 'synced'),
            'attention': sum(
                1 for worker in enabled_workers
                if worker.sync_state['state'] == 'error' or worker.error_status or worker.warnings['stopped_services']
                or worker.warnings['certificate_issues'] or not worker.is_online
            ),
        },
        'cache_refresh_interval': settings.WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL,
        'cache_enabled': settings.WIREGUARD_STATUS_CACHE_ENABLED,
        'cache_web_load_previous_count': settings.WIREGUARD_STATUS_CACHE_WEB_LOAD_PREVIOUS_COUNT,
        'master_cache_times': master_cache_times,
        'cluster_cache_times': cluster_cache_times,
    }
    return render(request, 'cluster/workers_list.html', context)


@login_required
def worker_details(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    worker = describe_worker(get_object_or_404(Worker.objects.select_related('workerstatus'), uuid=request.GET.get('uuid')))
    cluster_settings, cluster_settings_created = ClusterSettings.objects.get_or_create(name='cluster_settings')

    sections = []
    for section_name in SECTION_NAMES:
        section_state = worker.sync_state['sections'].get(section_name, {})
        reported = (worker.status.section_status or {}).get(section_name, {}) if worker.status else {}
        sections.append({
            'name': section_name,
            'state': section_state.get('state', 'pending'),
            'message': section_state.get('message', ''),
            'updated': parse_datetime(reported.get('updated', '')) if reported.get('updated') else None,
        })

    certificates = []
    if worker.status:
        for hostname, certificate in sorted((worker.status.certificate_status or {}).items()):
            certificates.append({
                'hostname': hostname,
                'status': certificate.get('status', ''),
                'issuer': certificate.get('issuer', ''),
                'not_after': parse_datetime(certificate['not_after']) if certificate.get('not_after') else None,
            })

    webadmin_hostnames = get_webadmin_hostnames()
    primary_address = f"https://{webadmin_hostnames[0] if webadmin_hostnames else request.get_host()}"

    context = {
        'page_title': worker.name,
        'worker': worker,
        'cluster_settings': cluster_settings,
        'current_worker_version': settings.CLUSTER_WORKER_CURRENT_VERSION,
        'distributed': ClusterSettings.is_distributed(),
        'sections': sections,
        'certificates': certificates,
        'primary_address': primary_address,
        'time_zone': settings.TIME_ZONE,
    }
    return render(request, 'cluster/worker_details.html', context)


@login_required
def worker_manage(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    worker = None
    if 'uuid' in request.GET:
        worker = get_object_or_404(Worker, uuid=request.GET['uuid'])
        page_title = _('Edit Worker: ') + worker.name

        if request.GET.get('action') == 'delete':
            worker_name = worker.name
            if request.GET.get('confirmation') == 'delete':
                try:
                    worker.delete()
                    messages.success(request, _('Worker deleted|Worker deleted: ') + worker_name)
                except ProtectedError:
                    messages.warning(request, _(
                        'Worker not deleted|Move the WireGuard instances of this worker to another server first: '
                    ) + ', '.join(str(instance) for instance in worker.wireguard_instances.all()))
                    return redirect(reverse('worker_details') + f'?uuid={worker.uuid}')
            else:
                messages.warning(request, _('Worker not deleted|Invalid confirmation.'))
            return redirect(reverse('cluster_main'))
    else:
        page_title = _('Add Worker')

    form = WorkerForm(request.POST or None, instance=worker)
    if form.is_valid():
        is_new_worker = worker is None
        worker = form.save()
        if is_new_worker:
            messages.success(request, _('Worker created|Worker created: ') + worker.name)
        else:
            messages.success(request, _('Worker updated|Worker updated: ') + worker.name)
        return redirect(reverse('worker_details') + f'?uuid={worker.uuid}')

    form_description = {
        'size': 'col-lg-6',
        'content': _('''
        <h5>Worker</h5>
        <p>A worker is a cluster node that replicates WireGuard, firewall and DNS from this primary server and, optionally, publishes App Gateway applications.</p>

        <h5>Name and location</h5>
        <p>Used to identify the worker. The <strong>hostname</strong> is the address clients use to connect to this worker: it is written as the endpoint of the peer configurations downloaded for this server.</p>

        <h5>Token</h5>
        <p>Secret used by the worker to authenticate with this primary server. Changing it disconnects the worker until its configuration is updated.</p>

        <h5>IP lock</h5>
        <p>When enabled, the worker is only accepted from the IP address below. Without it, the address is updated automatically from the last connection.</p>

        <h5>Enabled</h5>
        <p>Disabled workers are refused and shut down their WireGuard interfaces until enabled again.</p>
        ''')
    }

    context = {
        'page_title': page_title,
        'form': form,
        'worker': worker,
        'instance': worker,
        'form_description': form_description,
    }
    return render(request, 'generic_form.html', context)


@login_required
def cluster_settings(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    cluster_settings, cluster_settings_created = ClusterSettings.objects.get_or_create(name='cluster_settings')

    was_distributed = ClusterSettings.is_distributed()
    form = ClusterSettingsForm(request.POST or None, instance=cluster_settings)
    if form.is_valid():
        cluster_settings = form.save()
        messages.success(request, _('Cluster settings updated successfully.'))
        if ClusterSettings.is_distributed() != was_distributed:
            # Where each instance runs may have changed: workers synchronize the new files right away and the
            # primary server moves its interfaces when the configuration is applied
            export_wireguard_configuration()
            export_firewall_configuration()
            WireGuardInstance.objects.update(pending_changes=True)
        return redirect(reverse('cluster_main'))

    form_description = {
        'size': 'col-lg-6',
        'content': _('''
        <h5>Cluster Enabled</h5>
        <p>When disabled, workers are refused and shut down their WireGuard interfaces, and App Gateway applications are only published by this primary server. Requires the WireGuard status cache.</p>

        <h5>Primary Enable WireGuard</h5>
        <p>Lists this primary server as an option when downloading peer configurations and VPN invites.</p>

        <h5>Cluster Mode</h5>
        <p><strong>Mirror</strong>: every worker receives the same WireGuard instances, peers, firewall and DNS configuration. Peers can connect to any server.</p>
        <p><strong>Distributed</strong>: each WireGuard instance runs only on the server selected in the instance settings (the primary server by default). Peers connect to that server. Firewall rules cannot be bound to a specific instance interface: use wg+ or IP addresses. After changing the mode, apply the WireGuard configuration so the primary server stops the instances that moved to workers.</p>

        <h5>Worker Display</h5>
        <p>How workers are named in server selections (peer configuration downloads and VPN invites).</p>
        ''')
    }

    context = {
        'page_title': _('Cluster Settings'),
        'form': form,
        'cluster_settings': cluster_settings,
        'instance': cluster_settings,
        'form_description': form_description,
    }
    return render(request, 'generic_form.html', context)
