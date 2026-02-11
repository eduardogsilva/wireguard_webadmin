from django.urls import path

from .views_api import api_v2_manage_peer

urlpatterns = [
    path('manage_peer/', api_v2_manage_peer, name='api_v2_manage_peer'),

]