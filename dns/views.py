from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from user_manager.models import UserAcl
from .models import DNSSettings, StaticHost
from .forms import StaticHostForm, DNSSettingsForm
from .functions import generate_dnsmasq_config
from django.conf import settings


@login_required
def view_apply_dns_config(request):
    dns_settings, _ = DNSSettings.objects.get_or_create(name='dns_settings')
    dns_settings.pending_changes = False
    dns_settings.save()
    dnsmasq_config = generate_dnsmasq_config()
    with open(settings.DNS_CONFIG_FILE, 'w') as f:
        f.write(dnsmasq_config)
    messages.success(request, 'DNS settings applied successfully')
    return redirect('/dns/')


@login_required
def view_static_host_list(request):
    dns_settings, _ = DNSSettings.objects.get_or_create(name='dns_settings')
    static_host_list = StaticHost.objects.all().order_by('hostname')
    if dns_settings.pending_changes:
        messages.warning(request, 'Pending Changes|There are pending DNS changes that have not been applied')
    context = {
        'dns_settings': dns_settings,
        'static_host_list': static_host_list,
    }
    return render(request, 'dns/static_host_list.html', context=context)


@login_required
def view_manage_dns_settings(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    dns_settings, _ = DNSSettings.objects.get_or_create(name='dns_settings')
    form = DNSSettingsForm(request.POST or None, instance=dns_settings)
    if form.is_valid():
        form.save()
        return redirect('/dns/apply_config/')

    form_description_content = '''
        <strong>DNS Forwarders</strong>
        <p>
        All DNS queries will be forwarded to the primary resolver. If the primary resolver is not available, the secondary resolver will be used.
        </p>
        
        '''

    context = {
        'dns_settings': dns_settings,
        'form': form,
        'form_description': {
            'size': '',
            'content': form_description_content
        },
    }
    return render(request, 'generic_form.html', context=context)


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
