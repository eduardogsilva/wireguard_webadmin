from django.urls import path

from cluster.views import cluster_main, cluster_settings, worker_manage

urlpatterns = [
    path('', cluster_main, name='cluster_main'),
    path('worker/manage/', worker_manage, name='worker_manage'),
    path('settings/', cluster_settings, name='cluster_settings'),
]
