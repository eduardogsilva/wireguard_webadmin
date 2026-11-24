from django.http import Http404
from django.shortcuts import render
from django.utils import timezone

from cluster.models import ClusterSettings
from vpn_invite.models import PeerInvite, InviteSettings
from wireguard_tools.functions import get_config_servers


def view_public_vpn_invite(request):
    PeerInvite.objects.filter(invite_expiration__lt=timezone.now()).delete()
    try:
        peer_invite = PeerInvite.objects.get(uuid=request.GET.get('token'))
        invite_settings = InviteSettings.objects.get(name='default_settings')
    except:
        raise Http404

    cluster_settings = ClusterSettings.objects.filter(name='cluster_settings', enabled=True).first()
    servers = get_config_servers(peer_invite.peer.wireguard_instance)

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
