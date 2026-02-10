from django.urls import path

from cluster.cluster_api import api_cluster_status, api_get_worker_config_files, api_get_worker_dnsmasq_config, \
    api_worker_ping, api_submit_worker_wireguard_stats

urlpatterns = [
    path('status/', api_cluster_status, name='api_cluster_status'),
    path('worker/get_config_files/', api_get_worker_config_files, name='api_get_worker_config_files'),
    path('worker/get_dnsmasq_config/', api_get_worker_dnsmasq_config, name='api_get_worker_dnsmasq_config'),
    path('worker/ping/', api_worker_ping, name='api_worker_ping'),
    path('worker/submit_wireguard_stats/', api_submit_worker_wireguard_stats, name='api_submit_worker_wireguard_stats'),
]
