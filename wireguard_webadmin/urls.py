"""
URL configuration for wireguard_webadmin project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from accounts.views import view_create_first_user, view_login, view_logout
from api.views import api_instance_info, api_peer_invite, api_peer_list, cron_check_updates, \
    cron_update_peer_latest_handshake, peer_info, routerfleet_authenticate_session, routerfleet_get_user_token, \
    wireguard_status
from console.views import view_console
from dns.views import view_apply_dns_config, view_manage_dns_settings, view_manage_filter_list, view_manage_static_host, \
    view_static_host_list, view_toggle_dns_list, view_update_dns_list
from firewall.views import manage_firewall_rule, manage_redirect_rule, view_firewall_migration_required, \
    view_firewall_rule_list, view_generate_iptables_script, view_manage_firewall_settings, view_redirect_rule_list, \
    view_reset_firewall
from intl_tools.views import view_change_language
from user_manager.views import view_manage_user, view_peer_group_list, view_peer_group_manage, view_user_list
from vpn_invite.views import view_email_settings, view_vpn_invite_list, view_vpn_invite_settings
from vpn_invite_public.views import view_public_vpn_invite
from wgrrd.views import view_rrd_graph
from wireguard.views import view_apply_db_patches, view_wireguard_manage_instance, view_wireguard_status
from wireguard_peer.views import view_manage_ip_address, view_wireguard_peer_list, view_wireguard_peer_manage, \
    view_wireguard_peer_sort
from wireguard_tools.views import download_config_or_qrcode, export_wireguard_configs, restart_wireguard_interfaces

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', view_apply_db_patches, name='apply_db_patches'),
    path('status/', view_wireguard_status, name='wireguard_status'),
    path('dns/', view_static_host_list, name='static_host_list'),
    path('dns/apply_config/', view_apply_dns_config, name='apply_dns_config'),
    path('dns/manage_static_host/', view_manage_static_host, name='manage_static_host'),
    path('dns/manage_settings/', view_manage_dns_settings, name='manage_dns_settings'),
    path('dns/manage_filter_list/', view_manage_filter_list, name='manage_filter_list'),
    path('dns/update_dns_list/', view_update_dns_list, name='update_dns_list'),
    path('dns/toggle_dns_list/', view_toggle_dns_list, name='toggle_dns_list'),
    path('peer/list/', view_wireguard_peer_list, name='wireguard_peer_list'),
    path('peer/sort/', view_wireguard_peer_sort, name='wireguard_peer_sort'),
    path('peer/manage/', view_wireguard_peer_manage, name='wireguard_peer_manage'),
    path('peer/manage_ip_address/', view_manage_ip_address, name='manage_ip_address'),
    path('rrd/graph/', view_rrd_graph, name='rrd_graph'),
    path('console/', view_console, name='console'),
    path('user/list/', view_user_list, name='user_list'),
    path('user/manage/', view_manage_user, name='manage_user'),
    path('user/peer-group/list/', view_peer_group_list, name='peer_group_list'),
    path('user/peer-group/manage/', view_peer_group_manage, name='peer_group_manage'),
    path('tools/export_wireguard_config/', export_wireguard_configs, name='export_wireguard_configs'),
    path('tools/download_peer_config/', download_config_or_qrcode, name='download_config_or_qrcode'),
    path('tools/restart_wireguard/', restart_wireguard_interfaces, name='restart_wireguard_interfaces'),
    path('server/manage/', view_wireguard_manage_instance, name='wireguard_manage_instance'),
    path('accounts/create_first_user/', view_create_first_user, name='create_first_user'),
    path('accounts/login/', view_login, name='login'),
    path('accounts/logout/', view_logout, name='logout'),
    path('accounts/routerfleet_authenticate_session/', routerfleet_authenticate_session, name='routerfleet_authenticate_session'),
    path('api/routerfleet_get_user_token/', routerfleet_get_user_token, name='routerfleet_get_user_token'),
    path('api/wireguard_status/', wireguard_status, name='api_wireguard_status'),
    path('api/peer_list/', api_peer_list, name='api_peer_list'),
    path('api/instance_info/', api_instance_info, name='api_instance_info'),
    path('api/peer_info/', peer_info, name='api_peer_info'),
    path('api/peer_invite/', api_peer_invite, name='api_peer_invite'),
    path('api/cron_check_updates/', cron_check_updates, name='cron_check_updates'),
    path('api/cron_update_peer_latest_handshake/', cron_update_peer_latest_handshake, name='cron_update_peer_latest_handshake'),
    path('firewall/port_forward/', view_redirect_rule_list, name='redirect_rule_list'),    
    path('firewall/manage_port_forward_rule/', manage_redirect_rule, name='manage_redirect_rule'),
    path('firewall/rule_list/', view_firewall_rule_list, name='firewall_rule_list'),
    path('firewall/manage_firewall_rule/', manage_firewall_rule, name='manage_firewall_rule'),
    path('firewall/firewall_settings/', view_manage_firewall_settings, name='firewall_settings'),
    path('firewall/generate_firewall_script/', view_generate_iptables_script, name='generate_iptables_script'),
    path('firewall/reset_to_default/', view_reset_firewall, name='reset_firewall'),
    path('firewall/migration_required/', view_firewall_migration_required, name='firewall_migration_required'),
    path('vpn_invite/', view_vpn_invite_list, name='vpn_invite_list'),
    path('vpn_invite/settings/', view_vpn_invite_settings, name='vpn_invite_settings'),
    path('vpn_invite/smtp_settings/', view_email_settings, name='email_settings'),
    path('invite/', view_public_vpn_invite, name='public_vpn_invite'),
    path('invite/download_config/', download_config_or_qrcode, name='download_config_or_qrcode'),
    path('change_language/', view_change_language, name='change_language'),
]
