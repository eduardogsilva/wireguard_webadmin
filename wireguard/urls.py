from django.urls import path

from wireguard.views import view_wireguard_manage_instance, view_server_list, view_server_detail

urlpatterns = [
    path('manage/', view_wireguard_manage_instance, name='wireguard_manage_instance'),
    path('list/', view_server_list, name='wireguard_server_list'),
    path('detail/', view_server_detail, name='wireguard_server_detail'),
]
