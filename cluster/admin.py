from django.contrib import admin

from .models import ClusterSettings, Worker, WorkerStatus


@admin.register(ClusterSettings)
class ClusterSettingsAdmin(admin.ModelAdmin):
    list_display = ('name', 'enabled', 'cluster_mode', 'created', 'updated')
    list_filter = ('enabled', 'cluster_mode', 'primary_enable_wireguard')


@admin.register(Worker)
class WorkerAdmin(admin.ModelAdmin):
    list_display = ('name', 'enabled', 'ip_address', 'country', 'city', 'ip_lock', 'created', 'updated')
    list_filter = ('enabled', 'ip_lock', 'country')


@admin.register(WorkerStatus)
class WorkerStatusAdmin(admin.ModelAdmin):
    list_display = ('worker', 'last_seen', 'worker_version', 'wireguard_status_updated')
    list_filter = ('last_seen',)

