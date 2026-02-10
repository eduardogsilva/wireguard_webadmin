from django.urls import path

from firewall.views import manage_firewall_rule, manage_redirect_rule, view_firewall_migration_required, \
    view_firewall_rule_list, view_generate_iptables_script, view_manage_firewall_settings, view_redirect_rule_list, \
    view_reset_firewall

urlpatterns = [
    path('port_forward/', view_redirect_rule_list, name='redirect_rule_list'),    
    path('manage_port_forward_rule/', manage_redirect_rule, name='manage_redirect_rule'),
    path('rule_list/', view_firewall_rule_list, name='firewall_rule_list'),
    path('manage_firewall_rule/', manage_firewall_rule, name='manage_firewall_rule'),
    path('firewall_settings/', view_manage_firewall_settings, name='firewall_settings'),
    path('generate_firewall_script/', view_generate_iptables_script, name='generate_iptables_script'),
    path('reset_to_default/', view_reset_firewall, name='reset_firewall'),
    path('migration_required/', view_firewall_migration_required, name='firewall_migration_required'),
]
