from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.utils.translation import gettext as _

from scheduler.forms import ScheduleProfileForm
from scheduler.forms import ScheduleSlotForm
from scheduler.models import ScheduleProfile, ScheduleSlot


@login_required
def view_scheduler_profile_list(request):
    profiles = ScheduleProfile.objects.all().order_by('name')
    context = {
        'profiles': profiles,
    }
    return render(request, 'scheduler/scheduleprofile_list.html', context)


@login_required
def view_manage_scheduler_profile(request):
    profile_uuid = request.GET.get('uuid')
    if profile_uuid:
        profile = get_object_or_404(ScheduleProfile, uuid=profile_uuid)
        title = _('Edit Schedule Profile')
        slots = profile.time_interval.all()
    else:
        profile = None
        title = _('Create Schedule Profile')
        slots = None

    if request.method == 'POST':
        form = ScheduleProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, _('Schedule Profile saved successfully.'))
            return redirect('scheduler_profile_list')
    else:
        form = ScheduleProfileForm(instance=profile)

    context = {
        'form': form,
        'title': title,
        'profile': profile,
        'slots': slots,
    }
    return render(request, 'scheduler/scheduleprofile_form.html', context)


@login_required
def view_delete_scheduler_profile(request):
    profile_uuid = request.GET.get('uuid')
    profile = get_object_or_404(ScheduleProfile, uuid=profile_uuid)

    if request.method == 'POST':
        profile.delete()
        messages.success(request, _('Schedule Profile deleted successfully.'))
        return redirect('scheduler_profile_list')

    context = {
        'object': profile,
        'title': _('Delete Schedule Profile'),
        'cancel_url': reverse('scheduler_profile_list'),
        'text': _('Are you sure you want to delete the profile "%(name)s"?') % {'name': profile.name}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_scheduler_slot(request):
    slot_uuid = request.GET.get('uuid')
    profile_uuid = request.GET.get('profile_uuid')
    
    if slot_uuid:
        slot = get_object_or_404(ScheduleSlot, uuid=slot_uuid)
        profile = slot.profile
        title = _('Edit Time Interval')
    else:
        profile = get_object_or_404(ScheduleProfile, uuid=profile_uuid)
        slot = None
        title = _('Add Time Interval')

    cancel_url = f"{reverse('manage_scheduler_profile')}?uuid={profile.uuid}"

    if request.method == 'POST':
        form = ScheduleSlotForm(request.POST, instance=slot, cancel_url=cancel_url)
        if form.is_valid():
            new_slot = form.save(commit=False)
            new_slot.profile = profile
            new_slot.save()
            messages.success(request, _('Time Interval saved successfully.'))
            return redirect(cancel_url)
    else:
        form = ScheduleSlotForm(instance=slot, cancel_url=cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
        'profile': profile,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_scheduler_slot(request):
    slot_uuid = request.GET.get('uuid')
    slot = get_object_or_404(ScheduleSlot, uuid=slot_uuid)
    profile = slot.profile
    cancel_url = f"{reverse('manage_scheduler_profile')}?uuid={profile.uuid}"

    if request.method == 'POST':
        slot.delete()
        messages.success(request, _('Time Interval deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'object': slot,
        'title': _('Delete Time Interval'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete this time interval?')
    }
    return render(request, 'scheduler/generic_delete_confirm.html', context)
