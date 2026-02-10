from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # Core / entrypoint
    path('', include('wireguard.urls_root')),

    # Auth & users
    path('accounts/', include('accounts.urls')),
    path('user/', include('user_manager.urls')),

    # API
    path('api/', include('api.urls')),
    path('manage_api/v2/', include('api_v2.urls_manage')),

    # Main features
    path('cluster/', include('cluster.urls_manage')),
    path('dns/', include('dns.urls')),
    path('firewall/', include('firewall.urls')),
    path('peer/', include('wireguard_peer.urls')),
    path('routing-templates/', include('routing_templates.urls')),
    path('scheduler/', include('scheduler.urls')),
    path('server/', include('wireguard.urls')),
    path('tools/', include('wireguard_tools.urls')),
    path('vpn_invite/', include('vpn_invite.urls')),
    path('invite/', include('vpn_invite_public.urls')),

    # Utilities / misc
    path('console/', include('console.urls')),
    path('rrd/', include('wgrrd.urls')),
    path('change_language/', include('intl_tools.urls')),
]

