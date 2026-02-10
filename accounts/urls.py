from django.urls import path

from accounts.views import view_create_first_user, view_login, view_logout
from api.views import routerfleet_authenticate_session

urlpatterns = [
    path('create_first_user/', view_create_first_user, name='create_first_user'),
    path('login/', view_login, name='login'),
    path('logout/', view_logout, name='logout'),
    path('routerfleet_authenticate_session/', routerfleet_authenticate_session, name='routerfleet_authenticate_session'),
]