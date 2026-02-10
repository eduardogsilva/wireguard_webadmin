from django.urls import path

from vpn_invite.views import view_email_settings, view_vpn_invite_list, view_vpn_invite_settings

urlpatterns = [
    path('', view_vpn_invite_list, name='vpn_invite_list'),
    path('settings/', view_vpn_invite_settings, name='vpn_invite_settings'),
    path('smtp_settings/', view_email_settings, name='email_settings'),
]
