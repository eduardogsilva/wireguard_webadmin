from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.db.models import Max
from firewall.models import RedirectRule, FirewallRule, FirewallSettings
from firewall.forms import RedirectRuleForm, FirewallRuleForm, FirewallSettingsForm
from django.contrib import messages
from wireguard.models import WireGuardInstance
from user_manager.models import UserAcl
from firewall.tools import export_user_firewall, generate_firewall_header, generate_firewall_footer, generate_port_forward_firewall, reset_firewall_to_default
from django.contrib.auth.decorators import login_required
from django.utils import timezone


@login_required
def view_redirect_rule_list(request):
    wireguard_instances = WireGuardInstance.objects.all().order_by('instance_id')
    if wireguard_instances.filter(legacy_firewall=True).exists():
        return redirect('/firewall/migration_required/')
    if wireguard_instances.filter(pending_changes=True).exists():
        pending_changes_warning = True
    else:
        pending_changes_warning = False
    context = {
        'page_title': 'Port Forward List',
        'pending_changes_warning': pending_changes_warning,
        'redirect_rule_list': RedirectRule.objects.all().order_by('port'),
        'current_chain': 'portforward',
        }
    return render(request, 'firewall/redirect_rule_list.html', context=context)


@login_required
def manage_redirect_rule(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=40).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    context = {'page_title': 'Manage Port Forward'}
    instance = None
    uuid = request.GET.get('uuid', None)
    if uuid:
        instance = get_object_or_404(RedirectRule, uuid=uuid)
        if request.GET.get('action') == 'delete':
            if request.GET.get('confirmation') == instance.protocol + str(instance.port):
                instance.wireguard_instance.pending_changes = True
                instance.wireguard_instance.save()
                instance.delete()
                messages.success(request, 'Port Forward rule deleted successfully')
            else:
                messages.warning(request, 'Error deleting Port Forward rule|Confirmation did not match. Port Forward rule was not deleted.')
            return redirect('/firewall/port_forward/')

    if request.method == 'POST':
        form = RedirectRuleForm(request.POST, instance=instance)
        if form.is_valid():
            wireguard_instance = form.cleaned_data['wireguard_instance']
            wireguard_instance.pending_changes = True
            wireguard_instance.save()
            form.save()
            messages.success(request, 'Port Forward rule saved successfully')
            return redirect('/firewall/port_forward/')
    else:
        form = RedirectRuleForm(instance=instance)
    context['form'] = form
    context['instance'] = instance 
    
    return render(request, 'firewall/manage_redirect_rule.html', context=context)


@login_required
def view_firewall_rule_list(request):
    wireguard_instances = WireGuardInstance.objects.all().order_by('instance_id')
    if wireguard_instances.filter(legacy_firewall=True).exists():
        return redirect('/firewall/migration_required/')
    firewall_settings, firewall_settings_created = FirewallSettings.objects.get_or_create(name='global')
    if not firewall_settings.last_firewall_reset:
        reset_firewall_to_default()
        messages.success(request, 'VPN Firewall|Firewall initialized with the default rule set!')
        return redirect('/firewall/rule_list/')

    current_chain = request.GET.get('chain', 'forward')
    if current_chain not in ['forward', 'portforward', 'postrouting']:
        current_chain = 'forward'
    if wireguard_instances.filter(pending_changes=True).exists():
        pending_changes_warning = True
    else:
        pending_changes_warning = False
    context = {
        'page_title': 'Firewall Rule List',
        'pending_changes_warning': pending_changes_warning,
        'firewall_rule_list': FirewallRule.objects.filter(firewall_chain=current_chain).order_by('sort_order'),
        'current_chain': current_chain,
        'port_forward_list': RedirectRule.objects.all().order_by('port'),
        'firewall_settings': firewall_settings,
        'wireguard_instances': wireguard_instances,
        }
    return render(request, 'firewall/firewall_rule_list.html', context=context)


@login_required
def manage_firewall_rule(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=40).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    context = {'page_title': 'Manage Firewall Rule'}
    instance = None
    uuid = request.GET.get('uuid', None)
    if uuid:
        instance = get_object_or_404(FirewallRule, uuid=uuid)
        current_chain = instance.firewall_chain
        if request.GET.get('action') == 'delete':
            if request.GET.get('confirmation') == 'delete':
                firewall_settings, firewall_settings_created = FirewallSettings.objects.get_or_create(name='global')
                firewall_settings.pending_changes = True
                firewall_settings.save()
                instance.delete()
                # Marking wireguard_instance as having pending changes, not the best way to do this, but it works for now.
                # I will improve it later.
                wireguard_instance = WireGuardInstance.objects.all().first()
                if wireguard_instance:
                    wireguard_instance.pending_changes = True
                    wireguard_instance.save()
                messages.success(request, 'Firewall rule deleted successfully')
            else:
                messages.warning(request, 'Error deleting Firewall rule|Confirmation did not match. Firewall rule was not deleted.')
            return redirect('/firewall/rule_list/')
    else:
        current_chain = request.GET.get('chain', 'forward')

    if request.method == 'POST':
        form = FirewallRuleForm(request.POST, instance=instance, current_chain=current_chain)
        if form.is_valid():
            firewall_settings, firewall_settings_created = FirewallSettings.objects.get_or_create(name='global')
            firewall_settings.pending_changes = True
            firewall_settings.save()
            form.save()
            messages.success(request, 'Firewall rule saved successfully')
            # Marking wireguard_instance as having pending changes, not the best way to do this, but it works for now.
            # I will improve it later.
            wireguard_instance = WireGuardInstance.objects.all().first()
            if wireguard_instance:
                wireguard_instance.pending_changes = True
                wireguard_instance.save()
            return redirect('/firewall/rule_list/?chain=' + current_chain)
    else:
        form = FirewallRuleForm(instance=instance, current_chain=current_chain)
    context['form'] = form
    context['instance'] = instance 

    highest_forward_sort_order = FirewallRule.objects.filter(firewall_chain='forward').aggregate(Max('sort_order'))['sort_order__max']
    if highest_forward_sort_order is None:
        highest_forward_sort_order = 0

    highest_postrouting_sort_order = FirewallRule.objects.filter(firewall_chain='postrouting').aggregate(Max('sort_order'))['sort_order__max']
    if highest_postrouting_sort_order is None:
        highest_postrouting_sort_order = 0

    context['forward_sort_order'] = highest_forward_sort_order + 10
    context['postrouting_sort_order'] = highest_postrouting_sort_order + 10
    context['current_chain'] = current_chain
    
    return render(request, 'firewall/manage_firewall_rule.html', context=context)


@login_required
def view_manage_firewall_settings(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=40).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    context = {'page_title': 'Manage Firewall Settings'}
    previous_firewall_chain = request.GET.get('chain')
    if previous_firewall_chain not in ['forward', 'portforward', 'postrouting']:
        previous_firewall_chain = 'forward'

    if previous_firewall_chain == 'portforward':
        redirect_url = '/firewall/port_forward/'
    else:
        redirect_url = '/firewall/rule_list/?chain=' + previous_firewall_chain
        
    firewall_settings, firewall_settings_created = FirewallSettings.objects.get_or_create(name='global')

    if request.method == 'POST':
        form = FirewallSettingsForm(request.POST, instance=firewall_settings)
        if form.is_valid():
            form.save()
            messages.success(request, 'Firewall settings saved successfully')
            # Marking wireguard_instance as having pending changes, not the best way to do this, but it works for now.
            # I will improve it later.
            wireguard_instance = WireGuardInstance.objects.all().first()
            if wireguard_instance:
                wireguard_instance.pending_changes = True
                wireguard_instance.save()
            return redirect(redirect_url)
    else:
        form = FirewallSettingsForm(instance=firewall_settings)
    context['form'] = form
    context['instance'] = firewall_settings
    context['back_url'] = redirect_url

    return render(request, 'firewall/manage_firewall_settings.html', context=context)


@login_required
def view_generate_iptables_script(request):
    data = {'status': 'ok'}
    #firewall_header = generate_firewall_header()
    #port_forward_firewall = generate_port_forward_firewall()
    #user_firewall = export_user_firewall()
    #firewall_footer = generate_firewall_footer()
    #print(port_forward_firewall)
    #print(firewall_header)
    #print(user_firewall)
    #print(firewall_footer)
    
    return JsonResponse(data)


@login_required
def view_reset_firewall(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=40).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    if request.GET.get('confirmation') == 'delete all rules and reset firewall':
        reset_firewall_to_default()
        messages.success(request, 'VPN Firewall|Firewall reset to default successfully!')
    else:
        messages.warning(request, 'VPN Firewall|Firewall was not reset to default. Confirmation did not match.')
    return redirect('/firewall/rule_list/')


@login_required
def view_firewall_migration_required(request):
    if not WireGuardInstance.objects.filter(legacy_firewall=True).exists():
        messages.warning(request, 'No Firewall Migration pending|No WireGuard instances with legacy firewall settings found.')
        return redirect('/firewall/rule_list/')
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=40).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    
    return render(request, 'firewall/firewall_migration_required.html')