import base64
import os
import subprocess
import tempfile

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404

from user_manager.models import UserAcl
from wgwadmlibrary.tools import user_has_access_to_peer
from wireguard.models import Peer, WireGuardInstance


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

    dark_mode = request.GET.get('dark') == '1'

    command = [
        "rrdtool", "graph", graph_file,
        "--start", f"-{period}",
        "--title", f"{graph_title}",
        "--vertical-label", "Value",
    ]

    if dark_mode:
        command += [
            "--color", "BACK#2d3035",
            "--color", "CANVAS#353a40",
            "--color", "SHADEA#2d3035",
            "--color", "SHADEB#2d3035",
            "--color", "GRID#555c63",
            "--color", "MGRID#6c7580",
            "--color", "FONT#c8c8c8",
            "--color", "FRAME#2d3035",
            "--color", "ARROW#c8c8c8",
        ]
        tx_color = "4a9eff"
        rx_color = "ff6b6b"
    else:
        tx_color = "0000FF"
        rx_color = "FF0000"

    command += [
        f"DEF:txdata={rrd_file_path}:tx:AVERAGE",
        f"DEF:rxdata={rrd_file_path}:rx:AVERAGE",
        "CDEF:tx_mb=txdata,1048576,/",
        "CDEF:rx_mb=rxdata,1048576,/",
        "VDEF:tx_total=tx_mb,TOTAL",
        "VDEF:rx_total=rx_mb,TOTAL",
        f"LINE1:txdata#{tx_color}:Transmitted ",
        "GPRINT:tx_total:%6.2lf MB",
        "COMMENT:\\n",
        f"LINE1:rxdata#{rx_color}:Received ",
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




