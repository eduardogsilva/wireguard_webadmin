from django.db import transaction
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

from .models import ScheduleSlot, ScheduleProfile, PeerScheduling


def _recalc_profile_and_reset_peers(profile_id: int | None) -> None:
    if not profile_id:
        return

    has_slots = ScheduleSlot.objects.filter(profile_id=profile_id).exists()

    ScheduleProfile.objects.filter(pk=profile_id).update(active=has_slots)

    PeerScheduling.objects.filter(profile_id=profile_id).update(
        next_scheduled_enable_at=None,
        next_scheduled_disable_at=None,
    )


@receiver(post_save, sender=ScheduleSlot)
def scheduleslot_post_save(sender, instance: ScheduleSlot, created: bool, **kwargs):
    transaction.on_commit(lambda: _recalc_profile_and_reset_peers(instance.profile_id))


@receiver(post_delete, sender=ScheduleSlot)
def scheduleslot_post_delete(sender, instance: ScheduleSlot, **kwargs):
    transaction.on_commit(lambda: _recalc_profile_and_reset_peers(instance.profile_id))
