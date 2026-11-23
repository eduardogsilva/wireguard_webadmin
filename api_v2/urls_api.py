from django.urls import path

from .views_api import (
    api_v2_manage_cluster_manage_status,
    api_v2_manage_cluster_status,
    api_v2_manage_dns_record,
    api_v2_manage_peer,
    api_v2_peer_detail,
    api_v2_peer_list,
    api_v2_wireguard_status,
)

urlpatterns = [
    path('manage_peer/', api_v2_manage_peer, name='api_v2_manage_peer'),
    path('manage_dns_record/', api_v2_manage_dns_record, name='api_v2_manage_dns_record'),
    path('peer_list/', api_v2_peer_list, name='api_v2_peer_list'),
    path('peer_detail/', api_v2_peer_detail, name='api_v2_peer_detail'),
    path('wireguard_status/', api_v2_wireguard_status, name='api_v2_wireguard_status'),
    path('manage_cluster/status/', api_v2_manage_cluster_status, name='api_v2_manage_cluster_status'),
    path('manage_cluster/manage_status/', api_v2_manage_cluster_manage_status, name='api_v2_manage_cluster_manage_status'),
]
