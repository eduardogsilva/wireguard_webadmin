import uuid
from datetime import datetime, timedelta

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from wireguard.models import Peer

WEEK_DAYS = [
    (0, _("Monday")),
    (1, _("Tuesday")),
    (2, _("Wednesday")),
    (3, _("Thursday")),
    (4, _("Friday")),
    (5, _("Saturday")),
    (6, _("Sunday")),
]

class ScheduleProfile(models.Model):
    name = models.CharField(max_length=100)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(editable=False, default=uuid.uuid4)

    def __str__(self):
        return self.name

    @staticmethod
    def _next_weekday_time(now, weekday, t):

        tz = timezone.get_current_timezone()

        today = timezone.localdate(now)
        candidate_date = today + timedelta(days=(weekday - today.weekday()) % 7)

        candidate = timezone.make_aware(
            datetime.combine(candidate_date, t),
            tz
        )

        if candidate <= now:
            candidate_date += timedelta(days=7)
            candidate = timezone.make_aware(
                datetime.combine(candidate_date, t),
                tz
            )

        return candidate

    @property
    def next_dates(self):
        slots = list(self.time_interval.all())
        if not slots:
            return {'enable': None, 'disable': None}

        now = timezone.now()

        start_candidates = []
        end_candidates = []

        for slot in slots:
            start_dt = ScheduleProfile._next_weekday_time(now, slot.start_weekday, slot.start_time)
            end_dt = ScheduleProfile._next_weekday_time(now, slot.end_weekday, slot.end_time)

            start_candidates.append(start_dt)
            end_candidates.append(end_dt)

        return {
            'enable': min(start_candidates) if start_candidates else None,
            'disable': min(end_candidates) if end_candidates else None,
        }


class ScheduleSlot(models.Model):
    profile = models.ForeignKey(ScheduleProfile, on_delete=models.CASCADE, related_name="time_interval")
    start_weekday = models.PositiveSmallIntegerField(choices=WEEK_DAYS)
    end_weekday = models.PositiveSmallIntegerField(choices=WEEK_DAYS)
    start_time = models.TimeField()
    end_time = models.TimeField()

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(editable=False, default=uuid.uuid4)

    class Meta:
        ordering = ("start_weekday", "start_time")
        constraints = [
            models.UniqueConstraint(
                fields=["profile", "start_weekday", "end_weekday", "start_time", "end_time"],
                name="uniq_slot_per_profile"
            ),
        ]


class PeerScheduling(models.Model):
    peer = models.OneToOneField(Peer, on_delete=models.CASCADE, related_name="schedule")
    profile = models.ForeignKey(ScheduleProfile, on_delete=models.SET_NULL, null=True, blank=True)

    next_scheduled_enable_at = models.DateTimeField(null=True, blank=True)
    next_scheduled_disable_at = models.DateTimeField(null=True, blank=True)

    next_manual_suspend_at = models.DateTimeField(null=True, blank=True)
    next_manual_unsuspend_at = models.DateTimeField(null=True, blank=True)
    manual_suspend_reason = models.TextField(null=True, blank=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(editable=False, default=uuid.uuid4)

    class Meta:
        indexes = [
            models.Index(fields=["next_scheduled_enable_at"]),
            models.Index(fields=["next_scheduled_disable_at"]),
            models.Index(fields=["next_manual_suspend_at"]),
            models.Index(fields=["next_manual_unsuspend_at"]),
        ]