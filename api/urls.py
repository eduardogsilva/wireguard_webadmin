from django.urls import path, include

from api.views import api_instance_info, api_peer_invite, api_peer_list, cron_check_updates, \
    cron_update_peer_latest_handshake, peer_info, routerfleet_get_user_token, \
    wireguard_status, cron_refresh_wireguard_status_cache, cron_calculate_peer_schedules, cron_peer_scheduler

urlpatterns = [
    path('v2/', include('api_v2.urls_api')),
    path('cluster/', include('cluster.urls_api')),
    path('routerfleet_get_user_token/', routerfleet_get_user_token, name='routerfleet_get_user_token'),
    path('wireguard_status/', wireguard_status, name='api_wireguard_status'),
    path('peer_list/', api_peer_list, name='api_peer_list'),
    path('instance_info/', api_instance_info, name='api_instance_info'),
    path('peer_info/', peer_info, name='api_peer_info'),
    path('peer_invite/', api_peer_invite, name='api_peer_invite'),
    path('cron/peer_scheduler/', cron_peer_scheduler, name='cron_peer_scheduler'),
    path('cron/calculate_peer_schedules/', cron_calculate_peer_schedules, name='cron_calculate_peer_schedules'),
    path('cron/refresh_wireguard_status_cache/', cron_refresh_wireguard_status_cache, name='cron_refresh_wireguard_status_cache'),
    path('cron/check_updates/', cron_check_updates, name='cron_check_updates'),
    path('cron/update_peer_latest_handshake/', cron_update_peer_latest_handshake, name='cron_update_peer_latest_handshake'),
]