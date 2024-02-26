from django.shortcuts import render, get_object_or_404, redirect
from firewall.models import RedirectRule
from firewall.forms import RedirectRuleForm
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
        'redirect_rule_list': RedirectRule.objects.all().order_by('wireguard_instance', 'protocol', 'port')
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