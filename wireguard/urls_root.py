from django.urls import path

from wireguard.views import view_apply_db_patches, view_wireguard_status

urlpatterns = [
    path('', view_apply_db_patches, name='apply_db_patches'),
    path('status/', view_wireguard_status, name='wireguard_status'),
]
