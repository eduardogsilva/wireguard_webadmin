from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from user_manager.models import UserAcl
from .models import InviteSettings, PeerInvite
from django.conf import settings
from django.utils import timezone


@login_required
def view_vpn_invite_settings(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    if request.GET.get('invite') and request.GET.get('action') == 'delete':
        PeerInvite.objects.filter(uuid=request.GET.get('invite')).delete()
        return redirect('/vpn_invite/')

    try:
        default_invite_url = f'{settings.CSRF_TRUSTED_ORIGINS[1]}/invite/'
    except:
        default_invite_url = 'https://wireguard-webadmin.example.com/invite/'

    invite_settings, _ = InviteSettings.objects.get_or_create(
        name='default_settings', defaults={'invite_url': default_invite_url,}
    )

    if invite_settings.invite_url.startswith('http://'):
        invite_settings.invite_url = invite_settings.invite_url.replace('http://', 'https://')
        invite_settings.save()

    peer_invite_list = PeerInvite.objects.all().order_by('invite_expiration')
    peer_invite_list.filter(invite_expiration__lt=timezone.now()).delete()


    data = {
        'page_title': 'VPN Invite',
        'peer_invite_list': peer_invite_list,

    }

    return render(request, 'vpn_invite/invite_settings.html', context=data)