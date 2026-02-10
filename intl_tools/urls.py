from django.urls import path

from intl_tools.views import view_change_language

urlpatterns = [
    path('', view_change_language, name='change_language'),
]
