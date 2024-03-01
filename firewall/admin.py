from django.contrib import admin
from firewall.models import RedirectRule, FirewallRule, FirewallSettings


class RedirectRuleAdmin(admin.ModelAdmin):
    list_display = ('protocol', 'port', 'add_forward_rule', 'peer', 'wireguard_instance', 'ip_address', 'description', 'created', 'updated', 'uuid')
    search_fields = ('protocol', 'port', 'add_forward_rule', 'peer', 'wireguard_instance', 'ip_address', 'description', 'created', 'updated', 'uuid')

admin.site.register(RedirectRule, RedirectRuleAdmin)


class FirewallRuleAdmin(admin.ModelAdmin):
    list_display = ('firewall_chain', 'description', 'in_interface', 'out_interface', 'source_ip', 'source_netmask', 'source_peer_include_networks', 'not_source', 'destination_ip', 'destination_netmask', 'destination_peer_include_networks', 'not_destination', 'protocol', 'destination_port', 'state_new', 'state_related', 'state_established', 'state_invalid', 'state_untracked', 'not_state', 'rule_action', 'sort_order')
    search_fields = ('firewall_chain', 'description', 'in_interface', 'out_interface', 'source_ip', 'source_netmask', 'source_peer_include_networks', 'not_source', 'destination_ip', 'destination_netmask', 'destination_peer_include_networks', 'not_destination', 'protocol', 'destination_port', 'state_new', 'state_related', 'state_established', 'state_invalid', 'state_untracked', 'not_state', 'rule_action', 'sort_order')

admin.site.register(FirewallRule, FirewallRuleAdmin)


class FirewallSettingsAdmin(admin.ModelAdmin):
    list_display = ('wan_interface', 'default_forward_policy', 'default_output_policy', 'allow_peer_to_peer', 'allow_instance_to_instance')

admin.site.register(FirewallSettings, FirewallSettingsAdmin)

