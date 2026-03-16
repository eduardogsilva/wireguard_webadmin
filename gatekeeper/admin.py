from django.contrib import admin

from gatekeeper.models import (
    AuthMethod, AuthMethodAllowedDomain, AuthMethodAllowedEmail,
    GatekeeperGroup, GatekeeperIPAddress, GatekeeperUser,
)


class AuthMethodAdmin(admin.ModelAdmin):
    list_display = ('name', 'display_name', 'auth_type', 'session_expiration_minutes', 'created', 'updated')
    search_fields = ('name', 'display_name', 'auth_type')
    list_filter = ('auth_type',)

admin.site.register(AuthMethod, AuthMethodAdmin)


class AuthMethodAllowedDomainAdmin(admin.ModelAdmin):
    list_display = ('domain', 'auth_method', 'created', 'updated')
    search_fields = ('domain', 'auth_method__name', 'auth_method__display_name')

admin.site.register(AuthMethodAllowedDomain, AuthMethodAllowedDomainAdmin)


class AuthMethodAllowedEmailAdmin(admin.ModelAdmin):
    list_display = ('email', 'auth_method', 'created', 'updated')
    search_fields = ('email', 'auth_method__name', 'auth_method__display_name')

admin.site.register(AuthMethodAllowedEmail, AuthMethodAllowedEmailAdmin)


class GatekeeperUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'created', 'updated')
    search_fields = ('username', 'email')

admin.site.register(GatekeeperUser, GatekeeperUserAdmin)


class GatekeeperGroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'display_name', 'created', 'updated')
    search_fields = ('name', 'display_name')
    filter_horizontal = ('users',)

admin.site.register(GatekeeperGroup, GatekeeperGroupAdmin)


class GatekeeperIPAddressAdmin(admin.ModelAdmin):
    list_display = ('address', 'prefix_length', 'action', 'auth_method', 'description', 'created', 'updated')
    search_fields = ('address', 'description', 'auth_method__name', 'auth_method__display_name')
    list_filter = ('action',)

admin.site.register(GatekeeperIPAddress, GatekeeperIPAddressAdmin)
