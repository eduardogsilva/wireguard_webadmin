from django.urls import path

from api_v2.views import view_api_key_list, view_manage_api_key, view_delete_api_key

urlpatterns = [
    path('list/', view_api_key_list, name='api_v2_list'),
    path('manage/', view_manage_api_key, name='api_v2_manage'),
    path('delete/<uuid:uuid>/', view_delete_api_key, name='api_v2_delete'),
]