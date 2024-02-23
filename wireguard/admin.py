from django.contrib import admin
from .models import WireGuardInstance, Peer, PeerAllowedIP, WebadminSettings


class WireGuardInstanceAdmin(admin.ModelAdmin):
    list_display = ('name', 'instance_id', 'private_key', 'hostname', 'listen_port', 'address', 'netmask', 'post_up', 'post_down', 'created', 'updated', 'uuid')
    search_fields = ('name', 'instance_id', 'private_key', 'hostname', 'listen_port', 'address', 'netmask', 'post_up', 'post_down', 'created', 'updated', 'uuid')

admin.site.register(WireGuardInstance, WireGuardInstanceAdmin)


class PeerAdmin(admin.ModelAdmin):
    list_display = ('name', 'public_key', 'pre_shared_key', 'persistent_keepalive', 'wireguard_instance', 'created', 'updated', 'uuid')
    search_fields = ('name', 'public_key', 'pre_shared_key', 'persistent_keepalive', 'wireguard_instance', 'created', 'updated', 'uuid')

admin.site.register(Peer, PeerAdmin)


class PeerAllowedIPAdmin(admin.ModelAdmin):
    list_display = ('peer', 'priority', 'allowed_ip', 'netmask', 'created', 'updated', 'uuid')
    search_fields = ('peer', 'priority', 'allowed_ip', 'netmask', 'created', 'updated', 'uuid')

admin.site.register(PeerAllowedIP, PeerAllowedIPAdmin)


class WebadminSettingsAdmin(admin.ModelAdmin):
    list_display = ('current_version', 'latest_version', 'update_available', 'created', 'updated', 'uuid')
    search_fields = ('current_version', 'latest_version', 'update_available', 'created', 'updated', 'uuid')

#admin.site.register(WebadminSettings, WebadminSettingsAdmin)