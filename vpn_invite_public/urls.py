from django.urls import path

from vpn_invite_public.views import view_public_vpn_invite
from wireguard_tools.views import download_config_or_qrcode

urlpatterns = [
    path('', view_public_vpn_invite, name='public_vpn_invite'),
    path('download_config/', download_config_or_qrcode, name='download_config_or_qrcode'),
]
