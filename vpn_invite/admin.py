from django.contrib import admin
from .models import InviteSettings, PeerInvite


class PeerInviteAdmin(admin.ModelAdmin):
    list_display = ('peer', 'invite_expiration', 'created', 'updated', 'uuid')
admin.site.register(PeerInvite, PeerInviteAdmin)


class InviteSettingsAdmin(admin.ModelAdmin):
    list_display = ('name', 'uuid', 'created', 'updated')
admin.site.register(InviteSettings, InviteSettingsAdmin)
