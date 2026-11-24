from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _

from speed_profiles.forms import SpeedProfileForm
from speed_profiles.models import SpeedProfile
from user_manager.models import UserAcl
from wireguard.models import Peer, WireGuardInstance
from wireguard_peer.views import _auto_apply


def _can_manage(request):
    return UserAcl.objects.filter(user=request.user, user_level__gte=30).exists()


def apply_instances(request, instances):
    """Apply the configuration of the instances whose peers changed limits, or mark them as pending."""
    for instance in instances:
        if not _auto_apply(request, instance):
            WireGuardInstance.objects.filter(pk=instance.pk).update(pending_changes=True)


def instances_using(profile):
    return list(WireGuardInstance.objects.filter(peer__speed_profile=profile).distinct().order_by('instance_id'))


@login_required
def view_speed_profile_list(request):
    profiles = SpeedProfile.objects.annotate(peer_count=Count('peers')).order_by('name')
    return render(request, 'speed_profiles/speed_profile_list.html', {
        'page_title': _('Speed Profiles'), 'profiles': profiles,
    })


@login_required
def view_manage_speed_profile(request):
    if not _can_manage(request):
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    profile = None
    if request.GET.get('uuid'):
        profile = get_object_or_404(SpeedProfile, uuid=request.GET.get('uuid'))

    form = SpeedProfileForm(request.POST or None, instance=profile)
    if form.is_valid():
        changed = profile is not None and form.has_changed()
        profile = form.save()
        messages.success(request, _('Speed profile saved|Speed profile saved successfully.'))
        if changed:
            apply_instances(request, instances_using(profile))
        return redirect('speed_profile_list')

    form_description = {
        'size': 'col-lg-6',
        'content': _('''
        <h5>Download and upload</h5>
        <p><strong>Download</strong> is the traffic that reaches the peer and <strong>upload</strong> the traffic that
        it sends. The limit covers all the addresses and networks of the peer. Use 0 to leave a direction without
        limit. Peers without a profile have no limit.</p>

        <h5>Burst</h5>
        <p>The amount of data that may pass at full speed before the limit applies. It refills while the peer uses
        less than its limit.</p>
        <p>Web pages and most apps transfer a few MB at a time, so, depending on the case, a burst of 5 or 10 MB may
        improve browsing considerably: pages load at full speed, while long downloads and streams still run at the
        configured limit. For reference, 10 Mbit/s is about 1.25 MB per second.</p>
        <p>Use 0 to disable the burst.</p>
        '''),
    }
    return render(request, 'generic_form.html', {
        'page_title': _('Edit Speed Profile') if profile else _('Add Speed Profile'),
        'form': form,
        'form_description': form_description,
    })


@login_required
def view_delete_speed_profile(request):
    if not _can_manage(request):
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    profile = get_object_or_404(SpeedProfile, uuid=request.GET.get('uuid'))
    peers = list(Peer.objects.filter(speed_profile=profile).select_related('wireguard_instance').order_by(
        'wireguard_instance__instance_id', 'name'
    ))
    default_for_instances = list(profile.default_for_instances.order_by('instance_id'))

    if request.method == 'POST':
        if (peers or default_for_instances) and request.POST.get('action') != 'unlink_and_delete':
            return redirect(f"{request.path}?uuid={profile.uuid}")
        affected_instances = instances_using(profile)
        with transaction.atomic():
            Peer.objects.filter(speed_profile=profile).update(speed_profile=None)
            WireGuardInstance.objects.filter(default_speed_profile=profile).update(default_speed_profile=None)
            profile.delete()
        messages.success(request, _('Speed profile deleted|Speed profile deleted successfully.'))
        apply_instances(request, affected_instances)
        return redirect('speed_profile_list')

    return render(request, 'speed_profiles/speed_profile_delete.html', {
        'page_title': _('Delete Speed Profile'),
        'profile': profile,
        'peers': peers,
        'default_for_instances': default_for_instances,
    })
