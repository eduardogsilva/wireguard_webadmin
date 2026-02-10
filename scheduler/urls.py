from django.urls import path

from scheduler.views import view_scheduler_profile_list, view_manage_scheduler_profile, view_delete_scheduler_profile, \
    view_manage_scheduler_slot, view_delete_scheduler_slot

urlpatterns = [
    path('profile/list/', view_scheduler_profile_list, name='scheduler_profile_list'),
    path('profile/manage/', view_manage_scheduler_profile, name='manage_scheduler_profile'),
    path('profile/delete/', view_delete_scheduler_profile, name='delete_scheduler_profile'),
    path('slot/manage/', view_manage_scheduler_slot, name='manage_scheduler_slot'),
    path('slot/delete/', view_delete_scheduler_slot, name='delete_scheduler_slot'),
]
