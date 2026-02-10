from django.urls import path

from wgrrd.views import view_rrd_graph

urlpatterns = [
    path('graph/', view_rrd_graph, name='rrd_graph'),
]
