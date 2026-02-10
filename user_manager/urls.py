from django.urls import path

from user_manager.views import view_manage_user, view_peer_group_list, view_peer_group_manage, view_user_list

urlpatterns = [
    path('list/', view_user_list, name='user_list'),
    path('manage/', view_manage_user, name='manage_user'),
    path('peer-group/list/', view_peer_group_list, name='peer_group_list'),
    path('peer-group/manage/', view_peer_group_manage, name='peer_group_manage'),
]
