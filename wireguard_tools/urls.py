from django.urls import path

from wireguard_tools.views import download_config_or_qrcode, view_export_wireguard_configs, restart_wireguard_interfaces

urlpatterns = [
    path('export_wireguard_config/', view_export_wireguard_configs, name='export_wireguard_configs'),
    path('download_peer_config/', download_config_or_qrcode, name='download_config_or_qrcode'),
    path('restart_wireguard/', restart_wireguard_interfaces, name='restart_wireguard_interfaces'),
]
