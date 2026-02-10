from django.urls import path

from wireguard_peer.views import view_manage_ip_address, view_wireguard_peer_list, view_wireguard_peer_manage, \
    view_wireguard_peer_sort, view_apply_route_template, view_wireguard_peer_create, view_wireguard_peer_edit_field, \
    view_wireguard_peer_suspend, view_wireguard_peer_schedule_profile

urlpatterns = [
    path('list/', view_wireguard_peer_list, name='wireguard_peer_list'),
    path('sort/', view_wireguard_peer_sort, name='wireguard_peer_sort'),
    path('manage/', view_wireguard_peer_manage, name='wireguard_peer_manage'),
    path('create/', view_wireguard_peer_create, name='wireguard_peer_create'),
    path('edit/', view_wireguard_peer_edit_field, name='wireguard_peer_edit_field'),
    path('suspend/', view_wireguard_peer_suspend, name='wireguard_peer_suspend'),
    path('schedule_profile/', view_wireguard_peer_schedule_profile, name='wireguard_peer_schedule_profile'),
    path('apply_route_template/', view_apply_route_template, name='apply_route_template'),
    path('manage_ip_address/', view_manage_ip_address, name='manage_ip_address'),
]
