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
from wireguard.views import view_welcome, view_wireguard_status, view_wireguard_manage_instance
from wireguard_peer.views import view_wireguard_peer_list, view_wireguard_peer_manage, view_manage_ip_address
from console.views import view_console
from user_manager.views import view_user_list, view_manage_user
from accounts.views import view_create_first_user, view_login, view_logout
from wireguard_tools.views import export_wireguard_configs, download_config_or_qrcode, restart_wireguard_interfaces
from api.views import wireguard_status, cron_check_updates, cron_update_peer_latest_handshake
from firewall.views import view_redirect_rule_list, manage_redirect_rule, view_firewall_rule_list, manage_firewall_rule, view_manage_firewall_settings, view_generate_iptables_script


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', view_welcome, name='welcome'),
    path('status/', view_wireguard_status, name='wireguard_status'),
    path('peer/list/', view_wireguard_peer_list, name='wireguard_peer_list'),
    path('peer/manage/', view_wireguard_peer_manage, name='wireguard_peer_manage'),
    path('peer/manage_ip_address/', view_manage_ip_address, name='manage_ip_address'),
    path('console/', view_console, name='console'),
    path('user/list/', view_user_list, name='user_list'),
    path('user/manage/', view_manage_user, name='manage_user'),
    path('tools/export_wireguard_config/', export_wireguard_configs, name='export_wireguard_configs'),
    path('tools/download_peer_config/', download_config_or_qrcode, name='download_config_or_qrcode'),
    path('tools/restart_wireguard/', restart_wireguard_interfaces, name='restart_wireguard_interfaces'),
    path('server/manage/', view_wireguard_manage_instance, name='wireguard_manage_instance'),
    path('accounts/create_first_user/', view_create_first_user, name='create_first_user'),
    path('accounts/login/', view_login, name='login'),
    path('accounts/logout/', view_logout, name='logout'),
    path('api/wireguard_status/', wireguard_status, name='api_wireguard_status'),
    path('api/cron_check_updates/', cron_check_updates, name='cron_check_updates'),
    path('api/cron_update_peer_latest_handshake/', cron_update_peer_latest_handshake, name='cron_update_peer_latest_handshake'),
    path('firewall/port_forward/', view_redirect_rule_list, name='redirect_rule_list'),    
    path('firewall/manage_port_forward_rule/', manage_redirect_rule, name='manage_redirect_rule'),
    path('firewall/rule_list/', view_firewall_rule_list, name='firewall_rule_list'),
    path('firewall/manage_firewall_rule/', manage_firewall_rule, name='manage_firewall_rule'),
    path('firewall/firewall_settings/', view_manage_firewall_settings, name='firewall_settings'),
    path('firewall/generate_firewall_script/', view_generate_iptables_script, name='generate_iptables_script'),
]
