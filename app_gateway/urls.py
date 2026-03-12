from django.urls import path

from app_gateway import views

urlpatterns = [
    # Main Dashboard / List
    path('', views.view_app_gateway_list, name='app_gateway_list'),

    # Applications
    path('application/manage/', views.view_manage_application, name='manage_application'),
    path('application/delete/', views.view_delete_application, name='delete_application'),

    # Application Hosts
    path('host/manage/', views.view_manage_application_host, name='manage_application_host'),
    path('host/delete/', views.view_delete_application_host, name='delete_application_host'),

    # Access Policies
    path('policy/manage/', views.view_manage_access_policy, name='manage_access_policy'),
    path('policy/delete/', views.view_delete_access_policy, name='delete_access_policy'),

    # Application Default Policies
    path('app_policy/manage/', views.view_manage_application_policy, name='manage_application_policy'),
    path('app_policy/delete/', views.view_delete_application_policy, name='delete_application_policy'),

    # Application Routes
    path('route/manage/', views.view_manage_application_route, name='manage_application_route'),
    path('route/delete/', views.view_delete_application_route, name='delete_application_route'),
]
