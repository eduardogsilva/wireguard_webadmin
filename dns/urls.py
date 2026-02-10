from django.urls import path

from dns.views import view_apply_dns_config, view_manage_dns_settings, view_manage_filter_list, view_manage_static_host, \
    view_static_host_list, view_toggle_dns_list, view_update_dns_list

urlpatterns = [
    path('', view_static_host_list, name='static_host_list'),
    path('apply_config/', view_apply_dns_config, name='apply_dns_config'),
    path('manage_static_host/', view_manage_static_host, name='manage_static_host'),
    path('manage_settings/', view_manage_dns_settings, name='manage_dns_settings'),
    path('manage_filter_list/', view_manage_filter_list, name='manage_filter_list'),
    path('update_dns_list/', view_update_dns_list, name='update_dns_list'),
    path('toggle_dns_list/', view_toggle_dns_list, name='toggle_dns_list'),
]
