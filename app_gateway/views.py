from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.utils.translation import gettext as _

from app_gateway.forms import (
    ApplicationForm, ApplicationHostForm, AccessPolicyForm,
    ApplicationPolicyForm, ApplicationRouteForm
)
from app_gateway.models import (
    Application, ApplicationHost, AccessPolicy, ApplicationPolicy, ApplicationRoute
)
from user_manager.models import UserAcl


@login_required
def view_app_gateway_list(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=20).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    applications = Application.objects.all().order_by('name')
    hosts = ApplicationHost.objects.all().order_by('hostname')
    access_policies = AccessPolicy.objects.all().order_by('name')
    app_policies = ApplicationPolicy.objects.all().order_by('application__name')
    routes = ApplicationRoute.objects.all().order_by('application__name', 'order', 'path_prefix')

    tab = request.GET.get('tab', 'applications')

    context = {
        'applications': applications,
        'hosts': hosts,
        'access_policies': access_policies,
        'app_policies': app_policies,
        'routes': routes,
        'active_tab': tab,
    }
    return render(request, 'app_gateway/app_gateway_list.html', context)


@login_required
def view_manage_application(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_uuid = request.GET.get('uuid')

    if application_uuid:
        application = get_object_or_404(Application, uuid=application_uuid)
        title = _('Edit Application')
    else:
        application = None
        title = _('Create Application')

    cancel_url = reverse('app_gateway_list') + '?tab=applications'

    form = ApplicationForm(request.POST or None, instance=application, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('Application saved successfully.'))
        return redirect(cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_application(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application = get_object_or_404(Application, uuid=request.GET.get('uuid'))

    cancel_url = reverse('app_gateway_list') + '?tab=applications'

    if request.method == 'POST':
        application.delete()
        messages.success(request, _('Application deleted successfully.'))
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

    if application_host_uuid:
        application_host = get_object_or_404(ApplicationHost, uuid=application_host_uuid)
        title = _('Edit Application Host')
    else:
        application_host = None
        title = _('Add Application Host')

    cancel_url = reverse('app_gateway_list') + '?tab=hosts'

    form = ApplicationHostForm(request.POST or None, instance=application_host, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('Application Host saved successfully.'))
        return redirect(cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_application_host(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_host = get_object_or_404(ApplicationHost, uuid=request.GET.get('uuid'))

    cancel_url = reverse('app_gateway_list') + '?tab=hosts'

    if request.method == 'POST':
        application_host.delete()
        messages.success(request, _('Application Host deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'application_host': application_host,
        'title': _('Delete Application Host'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the host "%(hostname)s"?') % {'hostname': application_host.hostname}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_access_policy(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    access_policy_uuid = request.GET.get('uuid')

    if access_policy_uuid:
        access_policy = get_object_or_404(AccessPolicy, uuid=access_policy_uuid)
        title = _('Edit Access Policy')
    else:
        access_policy = None
        title = _('Create Access Policy')

    cancel_url = reverse('app_gateway_list') + '?tab=policies'

    form = AccessPolicyForm(request.POST or None, instance=access_policy, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('Access Policy saved successfully.'))
        return redirect(cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_access_policy(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    access_policy = get_object_or_404(AccessPolicy, uuid=request.GET.get('uuid'))

    cancel_url = reverse('app_gateway_list') + '?tab=policies'

    if request.method == 'POST':
        access_policy.delete()
        messages.success(request, _('Access Policy deleted successfully.'))
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

    if application_policy_uuid:
        application_policy = get_object_or_404(ApplicationPolicy, uuid=application_policy_uuid)
        title = _('Edit Application Default Policy')
    else:
        application_policy = None
        title = _('Set Application Default Policy')

    cancel_url = reverse('app_gateway_list') + '?tab=applications'


    form = ApplicationPolicyForm(request.POST or None, instance=application_policy, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('Application Default Policy saved successfully.'))
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

    cancel_url = reverse('app_gateway_list') + '?tab=applications'

    if request.method == 'POST':
        application_policy.delete()
        messages.success(request, _('Application Default Policy deleted successfully.'))
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

    if application_route_uuid:
        application_route = get_object_or_404(ApplicationRoute, uuid=application_route_uuid)
        title = _('Edit Application Route')
    else:
        application_route = None
        title = _('Add Application Route')

    cancel_url = reverse('app_gateway_list') + '?tab=routes'

    form = ApplicationRouteForm(request.POST or None, instance=application_route, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('Application Route saved successfully.'))
        return redirect(cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_application_route(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    application_route = get_object_or_404(ApplicationRoute, uuid=request.GET.get('uuid'))

    cancel_url = reverse('app_gateway_list') + '?tab=routes'

    if request.method == 'POST':
        application_route.delete()
        messages.success(request, _('Application Route deleted successfully.'))
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
