from django.shortcuts import render
from firewall.models import RedirectRule


def view_redirect_rule_list(request):
    context = {
        'page_title': 'Port Forward List',
        'redirect_rule_list': RedirectRule.objects.all().order_by('wireguard_instance', 'protocol', 'port')
        }
    return render(request, 'firewall/redirect_rule_list.html', context=context)


def manage_redirect_rule(request):
    context = {'page_title': 'Manage Port Forward'}
    return render(request, 'firewall/manage_redirect_rule.html', context=context)