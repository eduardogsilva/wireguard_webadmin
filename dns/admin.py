from django.contrib import admin

from .models import DNSFilterList, DNSSettings, StaticHost


class DNSFilterListAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'enabled', 'list_url', 'host_count', 'created', 'updated')
    list_filter = ('enabled', 'created', 'updated')
    search_fields = ('name', 'description', 'list_url')
    ordering = ('name', 'created')
admin.site.register(DNSFilterList, DNSFilterListAdmin)


class DNSSettingsAdmin(admin.ModelAdmin):
    list_display = ('dns_primary', 'dns_secondary', 'pending_changes', 'created', 'updated')
    list_filter = ('pending_changes', 'created', 'updated')
    search_fields = ('dns_primary', 'dns_secondary')
    ordering = ('created', 'updated')
admin.site.register(DNSSettings, DNSSettingsAdmin)


class StaticHostAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'ip_address', 'created', 'updated')
    search_fields = ('hostname', 'ip_address')
    ordering = ('hostname', 'created')
admin.site.register(StaticHost, StaticHostAdmin)