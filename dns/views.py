import hashlib
import os

import requests
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from user_manager.models import UserAcl
from .forms import DNSFilterListForm
from .forms import DNSSettingsForm, StaticHostForm
from .functions import generate_dnsmasq_config
from .models import DNSFilterList, DNSSettings
from .models import StaticHost


def export_dns_configuration():
    dns_settings, _ = DNSSettings.objects.get_or_create(name='dns_settings')
    dns_settings.pending_changes = False
    dns_settings.save()
    dnsmasq_config = generate_dnsmasq_config()
    with open(settings.DNS_CONFIG_FILE, 'w') as f:
        f.write(dnsmasq_config)
    return


@login_required
def view_apply_dns_config(request):
    export_dns_configuration()
    messages.success(request, _('DNS settings applied successfully'))
    return redirect('/dns/')


@login_required
def view_static_host_list(request):
    dns_settings, dns_settings_created = DNSSettings.objects.get_or_create(name='dns_settings')
    static_host_list = StaticHost.objects.all().order_by('hostname')
    filter_lists = DNSFilterList.objects.all().order_by('-recommended', 'name')
    if not filter_lists:
        DNSFilterList.objects.create(
            name='stevenblack-hosts', list_url='https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
            description='adware and malware', enabled=False, recommended=True
        )
        DNSFilterList.objects.create(
            name='stevenblack-fakenews', list_url='https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts',
            description='fakenews', enabled=False
        )
        DNSFilterList.objects.create(
            name='stevenblack-gambling',
            list_url='https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts',
            description='gambling', enabled=False
        )
        DNSFilterList.objects.create(
            name='stevenblack-porn',
            list_url='https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts',
            description='porn', enabled=False
        )
        DNSFilterList.objects.create(
            name='stevenblack-social',
            list_url='https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts',
            description='social', enabled=False
        )

        filter_lists = DNSFilterList.objects.all().order_by('-recommended', 'name')
        messages.success(request, _('Default DNS Filter List created successfully'))

    if dns_settings.pending_changes:
        messages.warning(request, _('Pending Changes|There are pending DNS changes that have not been applied'))
    context = {
        'dns_settings': dns_settings,
        'static_host_list': static_host_list,
        'filter_lists': filter_lists
    }
    return render(request, 'dns/static_host_list.html', context=context)


@login_required
def view_manage_dns_settings(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    dns_settings, dns_settings_created = DNSSettings.objects.get_or_create(name='dns_settings')
    form = DNSSettingsForm(request.POST or None, instance=dns_settings)
    if form.is_valid():
        form.save()
        return redirect('/dns/apply_config/')

    description_title = _('DNS Forwarders')
    description_message = _('All DNS queries will be forwarded to the primary resolver. If the primary resolver is not available, the secondary resolver will be used.')
    form_description_content = f'<strong>{description_title}</strong><p>{description_message}</p>'


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
    dns_settings, dns_settings_created = DNSSettings.objects.get_or_create(name='dns_settings')
    if request.GET.get('uuid'):
        static_dns = get_object_or_404(StaticHost, uuid=request.GET.get('uuid'))
        if request.GET.get('action') == 'delete':
            if request.GET.get('confirmation') == 'delete':
                static_dns.delete()
                dns_settings.pending_changes = True
                dns_settings.save()
                messages.success(request, _('Static DNS deleted successfully'))
                return redirect('/dns/')
            else:
                messages.warning(request, _('Static DNS not deleted|Invalid confirmation'))
                return redirect('/dns/')
    else:
        static_dns = None

    form = StaticHostForm(request.POST or None, instance=static_dns)
    if form.is_valid():
        form.save()
        dns_settings.pending_changes = True
        dns_settings.save()
        messages.success(request, _('Static DNS saved successfully'))
        return redirect('/dns/')

    context = {
        'dns_settings': dns_settings,
        'form': form,
        'instance': static_dns,
    }
    return render(request, 'generic_form.html', context=context)


@login_required
def view_manage_filter_list(request):
    if not UserAcl.objects.filter(user=request.user, user_level__gte=40).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})

    dns_settings, dns_settings_created = DNSSettings.objects.get_or_create(name='dns_settings')

    if request.GET.get('uuid'):
        filter_list = get_object_or_404(DNSFilterList, uuid=request.GET.get('uuid'))
        if request.GET.get('action') == 'delete':
            if request.GET.get('confirmation') == 'delete':
                if filter_list.enabled:
                    messages.warning(request, _('DNS Filter List not deleted | Filter List is enabled'))
                    return redirect('/dns/')
                file_path = os.path.join("/etc/dnsmasq/", f"{filter_list.uuid}.conf")
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        messages.error(request, _("Error removing config file: ") + e)
                        return redirect('/dns/')
                filter_list.delete()
                messages.success(request, _('DNS Filter List deleted successfully'))
                return redirect('/dns/')
            else:
                messages.warning(request, _('DNS Filter List not deleted | Invalid confirmation'))
                return redirect('/dns/')
    else:
        filter_list = None

    form = DNSFilterListForm(request.POST or None, instance=filter_list)
    if form.is_valid():
        form.save()
        dns_settings.pending_changes = True
        dns_settings.save()
        messages.success(request, _('DNS Filter List saved successfully'))
        return redirect('/dns/')

    context = {
        'dns_settings': dns_settings,
        'form': form,
        'instance': filter_list,
    }
    return render(request, 'generic_form.html', context=context)


@login_required
def view_update_dns_list(request):
    if not UserAcl.objects.filter(user=request.user, user_level__gte=40).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})

    dns_list = get_object_or_404(DNSFilterList, uuid=request.GET.get('uuid'))
    dns_settings, dns_settings_created = DNSSettings.objects.get_or_create(name='dns_settings')
    file_path = os.path.join("/etc/dnsmasq/", f"{dns_list.uuid}.conf")

    old_checksum = None
    if os.path.exists(file_path):
        try:
            with open(file_path, "rb") as f:
                old_content = f.read()
            old_checksum = hashlib.sha256(old_content).hexdigest()
        except Exception as e:
            messages.error(request, _("Failed to read existing config file: ") + e)
            if dns_list.enabled:
                dns_list.enabled = False
                dns_list.save()
                dns_settings.pending_changes = True
                dns_settings.save()
            return redirect('/dns/')

    try:
        response = requests.get(dns_list.list_url)
        response.raise_for_status()
        content = response.text
    except Exception as e:
        if dns_list.enabled:
            dns_list.enabled = False
            dns_list.save()
            dns_settings.pending_changes = True
            dns_settings.save()
        messages.error(request, _("Failed to fetch the host list: ") + e)
        return redirect('/dns/')

    new_checksum = hashlib.sha256(content.encode('utf-8')).hexdigest()

    # Write the new content to the file.
    try:
        with open(file_path, "w") as f:
            f.write(content)
    except Exception as e:
        messages.error(request, _("Failed to write config file: ") + e)
        if dns_list.enabled:
            dns_list.enabled = False
            dns_list.save()
            dns_settings.pending_changes = True
            dns_settings.save()
        return redirect('/dns/')

    # If the list is enabled and either the file did not exist or the checksum has changed,
    # mark the DNS settings as having pending changes.
    if dns_list.enabled and (old_checksum is None or new_checksum != old_checksum):
        dns_settings.pending_changes = True
        dns_settings.save()

    # Count the number of valid host entries (ignoring empty lines and lines starting with '#').
    host_count = sum(1 for line in content.splitlines() if line.strip() and not line.strip().startswith('#'))
    dns_list.host_count = host_count

    # If at least one valid host is found, update the last_updated field.
    if host_count > 0:
        dns_list.last_updated = timezone.now()

    # Save changes to the DNSFilterList instance.
    dns_list.save()

    messages.success(request, _('DNS Filter List updated successfully'))
    return redirect('/dns/')


def view_toggle_dns_list(request):
    if not UserAcl.objects.filter(user=request.user, user_level__gte=40).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})

    dns_list = get_object_or_404(DNSFilterList, uuid=request.GET.get('uuid'))
    dns_settings, dns_settings_created = DNSSettings.objects.get_or_create(name='dns_settings')
    file_path = os.path.join("/etc/dnsmasq/", f"{dns_list.uuid}.conf")

    if request.GET.get('action') == 'enable':
        if dns_list.host_count > 0 and os.path.exists(file_path):
            dns_list.enabled = True
            dns_list.save()
            export_dns_configuration()
            messages.success(request, _('DNS Filter List enabled successfully'))
        else:
            messages.error(request, _('DNS Filter List not enabled | No valid hosts found'))
    else:
        dns_list.enabled = False
        dns_list.save()
        export_dns_configuration()
        messages.success(request, _('DNS Filter List disabled successfully'))
    return redirect('/dns/')