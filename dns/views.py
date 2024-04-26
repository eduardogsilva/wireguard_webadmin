from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from user_manager.models import UserAcl
from .models import DNSSettings, StaticHost
from .forms import StaticHostForm


@login_required
def view_static_host_list(request):
    dns_settings, _ = DNSSettings.objects.get_or_create(name='dns_settings')
    static_host_list = StaticHost.objects.all().order_by('hostname')
    context = {
        'dns_settings': dns_settings,
        'static_host_list': static_host_list,
    }
    return render(request, 'dns/static_host_list.html', context=context)


@login_required
def view_manage_static_host(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=40).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    dns_settings, _ = DNSSettings.objects.get_or_create(name='dns_settings')
    if request.GET.get('uuid'):
        static_dns = get_object_or_404(StaticHost, uuid=request.GET.get('uuid'))
        if request.GET.get('action') == 'delete':
            if request.GET.get('confirmation') == 'delete':
                static_dns.delete()
                dns_settings.pending_changes = True
                dns_settings.save()
                messages.success(request, 'Static DNS deleted successfully')
                return redirect('/dns/')
            else:
                messages.warning(request, 'Static DNS not deleted|Invalid confirmation')
                return redirect('/dns/')
    else:
        static_dns = None

    form = StaticHostForm(request.POST or None, instance=static_dns)
    if form.is_valid():
        form.save()
        dns_settings.pending_changes = True
        dns_settings.save()
        messages.success(request, 'Static DNS saved successfully')
        return redirect('/dns/')

    context = {
        'dns_settings': dns_settings,
        'form': form,
        'instance': static_dns,
    }
    return render(request, 'generic_form.html', context=context)
