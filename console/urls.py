from django.urls import path

from console.views import view_console

urlpatterns = [
    path('', view_console, name='console'),
]
