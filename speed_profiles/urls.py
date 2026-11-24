from django.urls import path

from speed_profiles.views import view_delete_speed_profile, view_manage_speed_profile, view_speed_profile_list

urlpatterns = [
    path('', view_speed_profile_list, name='speed_profile_list'),
    path('manage/', view_manage_speed_profile, name='manage_speed_profile'),
    path('delete/', view_delete_speed_profile, name='delete_speed_profile'),
]
