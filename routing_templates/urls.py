from django.urls import path

from routing_templates.views import view_manage_routing_template, view_routing_template_list

urlpatterns = [
    path('list/', view_routing_template_list, name='routing_template_list'),
    path('manage/', view_manage_routing_template, name='manage_routing_template'),
]
