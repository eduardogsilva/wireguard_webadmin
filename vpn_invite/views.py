from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from user_manager.models import UserAcl
from wireguard_tools.models import EmailSettings
from .forms import EmailSettingsForm, InviteSettingsForm
from .models import InviteSettings, PeerInvite


@login_required
def view_vpn_invite_list(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    if request.GET.get('invite') and request.GET.get('action') == 'delete':
        PeerInvite.objects.filter(uuid=request.GET.get('invite')).delete()
        return redirect('/vpn_invite/')

    try:
        default_invite_url = f'{settings.CSRF_TRUSTED_ORIGINS[1]}/invite/'
    except:
        default_invite_url = 'https://wireguard-webadmin.example.com/invite/'

    invite_settings, invite_settings_created = InviteSettings.objects.get_or_create(
        name='default_settings', defaults={'invite_url': default_invite_url,}
    )

    if invite_settings.invite_url.startswith('http://'):
        invite_settings.invite_url = invite_settings.invite_url.replace('http://', 'https://')
        invite_settings.save()
    peer_invite_list = PeerInvite.objects.all().order_by('invite_expiration')
    peer_invite_list.filter(invite_expiration__lt=timezone.now()).delete()
    data = {
        'page_title': _('VPN Invite'),
        'peer_invite_list': peer_invite_list,
    }

    return render(request, 'vpn_invite/invite_settings.html', context=data)


@login_required
def view_vpn_invite_settings(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    invite_settings = InviteSettings.objects.get(name='default_settings')

    form = InviteSettingsForm(request.POST or None, instance=invite_settings)
    if form.is_valid():
        form.save()
        messages.success(request, _('Invite Settings|Settings saved successfully.'))
        return redirect('/vpn_invite/')
    data = {
        'invite_settings': invite_settings,
        'page_title': _('VPN Invite Settings'),
        'form': form,
        'form_size': 'col-lg-12'
    }
    return render(request, 'generic_form.html', context=data)


@login_required
def view_email_settings(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    email_settings, email_settings_created = EmailSettings.objects.get_or_create(name='email_settings')

    form = EmailSettingsForm(request.POST or None, instance=email_settings)
    if form.is_valid():
        form.save()
        messages.success(request, _('Email Settings|Settings saved successfully.'))
        return redirect('/vpn_invite/')
    data = {
        'email_settings': email_settings,
        'page_title': _('Email Settings'),
        'form': form,
        'form_size': 'col-lg-12'
    }
    return render(request, 'generic_form.html', context=data)
