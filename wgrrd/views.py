import subprocess

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse
from django.shortcuts import render, get_object_or_404

from user_manager.models import UserAcl
from wgwadmlibrary.tools import user_has_access_to_peer
from wireguard.models import Peer, WireGuardInstance

import base64
import tempfile
import os


@login_required
def view_rrd_graph(request):
    user_acl = get_object_or_404(UserAcl, user=request.user)
    peer = None
    instance = None
    if request.GET.get('peer'):
        peer = get_object_or_404(Peer, uuid=request.GET.get('peer'))
        if not user_has_access_to_peer(user_acl, peer):
            raise PermissionDenied
        graph_type = 'peer'
        rrd_filename = base64.urlsafe_b64encode(peer.public_key.encode()).decode().replace('=', '')
        rrd_file_path = f'/rrd_data/peers/{rrd_filename}.rrd'
        graph_title = f'Peer {peer}'
    elif request.GET.get('instance'):
        wireguard_instance = get_object_or_404(WireGuardInstance, uuid=request.GET.get('instance'))
        graph_type = 'instance'
        rrd_file_path = f'/rrd_data/wginstances/wg{wireguard_instance.instance_id}.rrd'
        graph_title = f'Instance wg{wireguard_instance.instance_id}'
    else:
        raise Http404

    if not os.path.exists(rrd_file_path):
        raise Http404

    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp_file:
        graph_file = tmp_file.name

    period = request.GET.get('period', '6h')
    if not (period[:-1].isdigit() and period[-1] in ['h', 'd']):
        period = '6h'

    command = [
        "rrdtool", "graph", graph_file,
        "--start", f"-{period}",
        "--title", f"{graph_title}",
        "--vertical-label", "Value",
        f"DEF:txdata={rrd_file_path}:tx:AVERAGE",
        f"DEF:rxdata={rrd_file_path}:rx:AVERAGE",
        "CDEF:tx_mb=txdata,1048576,/",
        "CDEF:rx_mb=rxdata,1048576,/",
        "VDEF:tx_total=tx_mb,TOTAL",
        "VDEF:rx_total=rx_mb,TOTAL",
        "LINE1:txdata#0000FF:Transmitted ",
        "GPRINT:tx_total:%6.2lf MB",
        "COMMENT:\\n",
        "LINE1:rxdata#FF0000:Received ",
        "GPRINT:rx_total:%6.2lf MB",
        "COMMENT:\\n"
    ]

    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE)
        with open(graph_file, 'rb') as f:
            image_data = f.read()
    finally:
        os.remove(graph_file)
    return HttpResponse(image_data, content_type="image/png")




