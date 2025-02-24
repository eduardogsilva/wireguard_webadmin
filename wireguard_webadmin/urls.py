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
from django.views.generic import RedirectView

from wireguard.views import view_wireguard_status, view_wireguard_manage_instance
from wireguard_peer.views import view_wireguard_peer_list, view_wireguard_peer_manage, view_manage_ip_address, view_wireguard_peer_sort
from console.views import view_console
from user_manager.views import view_user_list, view_manage_user, view_peer_group_list, view_peer_group_manage
from accounts.views import view_create_first_user, view_login, view_logout
from wireguard_tools.views import export_wireguard_configs, download_config_or_qrcode, restart_wireguard_interfaces
from api.views import wireguard_status, cron_check_updates, cron_update_peer_latest_handshake, routerfleet_get_user_token, routerfleet_authenticate_session, peer_info
from firewall.views import view_redirect_rule_list, manage_redirect_rule, view_firewall_rule_list, manage_firewall_rule, view_manage_firewall_settings, view_generate_iptables_script, view_reset_firewall, view_firewall_migration_required
from dns.views import view_static_host_list, view_manage_static_host, view_manage_dns_settings, view_apply_dns_config
from wgrrd.views import view_rrd_graph

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', RedirectView.as_view(url='/status/', permanent=False), name='redirect_to_status'),
    path('status/', view_wireguard_status, name='wireguard_status'),
    path('dns/', view_static_host_list, name='static_host_list'),
    path('dns/apply_config/', view_apply_dns_config, name='apply_dns_config'),
    path('dns/manage_static_host/', view_manage_static_host, name='manage_static_host'),
    path('dns/manage_settings/', view_manage_dns_settings, name='manage_dns_settings'),
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
    path('api/peer_info/', peer_info, name='api_peer_info'),
    path('api/cron_check_updates/', cron_check_updates, name='cron_check_updates'),
    path('api/cron_update_peer_latest_handshake/', cron_update_peer_latest_handshake, name='cron_update_peer_latest_handshake'),
    path('firewall/port_forward/', view_redirect_rule_list, name='redirect_rule_list'),    
    path('firewall/manage_port_forward_rule/', manage_redirect_rule, name='manage_redirect_rule'),
    path('firewall/rule_list/', view_firewall_rule_list, name='firewall_rule_list'),
    path('firewall/manage_firewall_rule/', manage_firewall_rule, name='manage_firewall_rule'),
    path('firewall/firewall_settings/', view_manage_firewall_settings, name='firewall_settings'),
    path('firewall/generate_firewall_script/', view_generate_iptables_script, name='generate_iptables_script'),
    path('firewall/reset_to_default/', view_reset_firewall, name='reset_firewall'),
    path('firewall/migration_required/', view_firewall_migration_required, name='firewall_migration_required')
]
