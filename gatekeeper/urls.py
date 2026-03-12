from django.urls import path

from gatekeeper import views

urlpatterns = [
    # Main Dashboard / List
    path('', views.view_gatekeeper_list, name='gatekeeper_list'),

    # Gatekeeper Users
    path('user/manage/', views.view_manage_gatekeeper_user, name='manage_gatekeeper_user'),
    path('user/delete/', views.view_delete_gatekeeper_user, name='delete_gatekeeper_user'),

    # Gatekeeper Groups
    path('group/manage/', views.view_manage_gatekeeper_group, name='manage_gatekeeper_group'),
    path('group/delete/', views.view_delete_gatekeeper_group, name='delete_gatekeeper_group'),

    # Auth Methods
    path('auth_method/manage/', views.view_manage_auth_method, name='manage_gatekeeper_auth_method'),
    path('auth_method/delete/', views.view_delete_auth_method, name='delete_gatekeeper_auth_method'),

    # Auth Method Allowed Domains
    path('domain/manage/', views.view_manage_auth_domain, name='manage_gatekeeper_domain'),
    path('domain/delete/', views.view_delete_auth_domain, name='delete_gatekeeper_domain'),

    # Auth Method Allowed Emails
    path('email/manage/', views.view_manage_auth_email, name='manage_gatekeeper_email'),
    path('email/delete/', views.view_delete_auth_email, name='delete_gatekeeper_email'),
]
