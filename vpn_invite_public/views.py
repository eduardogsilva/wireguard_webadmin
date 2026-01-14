from django.http import Http404
from django.shortcuts import render
from django.utils import timezone

from cluster.models import ClusterSettings, Worker
from vpn_invite.models import PeerInvite, InviteSettings


def view_public_vpn_invite(request):
    PeerInvite.objects.filter(invite_expiration__lt=timezone.now()).delete()
    try:
        peer_invite = PeerInvite.objects.get(uuid=request.GET.get('token'))
        invite_settings = InviteSettings.objects.get(name='default_settings')
    except:
        raise Http404

    cluster_settings = ClusterSettings.objects.filter(name='cluster_settings', enabled=True).first()
    servers = []
    if cluster_settings:
        if cluster_settings.primary_enable_wireguard:
            servers.append({'name': 'Primary Server', 'address': ''})
        
        for worker in Worker.objects.filter(enabled=True):
            listen_port = peer_invite.peer.wireguard_instance.listen_port
            worker_address = f"{worker.server_address}:{listen_port}"
            servers.append({'name': worker.display_name, 'address': worker_address})

    context = {
        'peer_invite': peer_invite,
        'invite_settings': invite_settings,
        'authenticated': False,
        'error': '',
        'cluster_settings': cluster_settings,
        'servers': servers
    }

    if request.method == 'POST':
        password = request.POST.get('password', '')
        # Check if the provided password matches the invite password
        if password and password == peer_invite.invite_password:
            context['authenticated'] = True
            context['password'] = password
        else:
            context['error'] = "Invalid password. Please try again."

    return render(request, 'vpn_invite/public_vpn_invite.html', context=context)
