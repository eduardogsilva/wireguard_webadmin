from django.contrib import admin

from app_gateway.models import (
    AccessPolicy, Application, ApplicationHost,
    ApplicationPolicy, ApplicationRoute,
)


class ApplicationHostInline(admin.TabularInline):
    model = ApplicationHost
    extra = 0


class ApplicationAdmin(admin.ModelAdmin):
    list_display = ('name', 'display_name', 'upstream', 'allow_invalid_cert', 'created', 'updated')
    search_fields = ('name', 'display_name', 'upstream')
    inlines = [ApplicationHostInline]

admin.site.register(Application, ApplicationAdmin)


class ApplicationHostAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'application', 'created', 'updated')
    search_fields = ('hostname', 'application__name', 'application__display_name')

admin.site.register(ApplicationHost, ApplicationHostAdmin)


class AccessPolicyAdmin(admin.ModelAdmin):
    list_display = ('name', 'display_name', 'policy_type', 'created', 'updated')
    search_fields = ('name', 'display_name')
    list_filter = ('policy_type',)
    filter_horizontal = ('groups', 'methods')

admin.site.register(AccessPolicy, AccessPolicyAdmin)


class ApplicationPolicyAdmin(admin.ModelAdmin):
    list_display = ('application', 'default_policy', 'created', 'updated')
    search_fields = ('application__name', 'application__display_name', 'default_policy__name')

admin.site.register(ApplicationPolicy, ApplicationPolicyAdmin)


class ApplicationRouteAdmin(admin.ModelAdmin):
    list_display = ('name', 'display_name', 'application', 'path_prefix', 'policy', 'order', 'created', 'updated')
    search_fields = ('name', 'display_name', 'path_prefix', 'application__name', 'application__display_name')
    list_filter = ('application',)

admin.site.register(ApplicationRoute, ApplicationRouteAdmin)
