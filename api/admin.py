from django.contrib import admin

from .models import WireguardStatusCache


# Register your models here.
class WireguardStatusCacheAdmin(admin.ModelAdmin):
    list_display = ('cache_type', 'processing_time_ms', 'created', 'updated')
    readonly_fields = ('uuid', 'created', 'updated')
admin.site.register(WireguardStatusCache, WireguardStatusCacheAdmin)