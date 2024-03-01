from django.shortcuts import render, get_object_or_404, redirect
from django.db.models import Max
from firewall.models import RedirectRule, FirewallRule, FirewallSettings
from firewall.forms import RedirectRuleForm, FirewallRuleForm
from django.contrib import messages
from wireguard.models import WireGuardInstance
from user_manager.models import UserAcl


def view_redirect_rule_list(request):
    wireguard_instances = WireGuardInstance.objects.all().order_by('instance_id')
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


def view_firewall_rule_list(request):
    wireguard_instances = WireGuardInstance.objects.all().order_by('instance_id')
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
        }
    return render(request, 'firewall/firewall_rule_list.html', context=context)


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
    
    return render(request, 'firewall/manage_firewall_rule.html', context=context)
