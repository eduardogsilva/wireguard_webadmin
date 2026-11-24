from django.urls import path

from cluster.cluster_api import api_legacy_cluster_status, api_manifest, api_report, api_section

urlpatterns = [
    path('status/', api_legacy_cluster_status, name='api_legacy_cluster_status'),
    path('v2/manifest/', api_manifest, name='api_cluster_manifest'),
    path('v2/section/<str:section_name>/', api_section, name='api_cluster_section'),
    path('v2/report/', api_report, name='api_cluster_report'),
]
