from django.contrib import admin
from firewall.models import RedirectRule


class RedirectRuleAdmin(admin.ModelAdmin):
    list_display = ('protocol', 'port', 'add_forward_rule', 'peer', 'wireguard_instance', 'ip_address', 'description', 'created', 'updated', 'uuid')
    search_fields = ('protocol', 'port', 'add_forward_rule', 'peer', 'wireguard_instance', 'ip_address', 'description', 'created', 'updated', 'uuid')

admin.site.register(RedirectRule, RedirectRuleAdmin)

