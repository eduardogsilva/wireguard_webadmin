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
    path('server/manage/', view_wireguard_manage_instance, name='wireguard_manage_instance'),
    path('accounts/create_first_user/', view_create_first_user, name='create_first_user'),
    path('accounts/login/', view_login, name='login'),
    path('accounts/logout/', view_logout, name='logout'),
]
