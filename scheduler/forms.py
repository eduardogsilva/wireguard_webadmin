from datetime import time

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, HTML, Div
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from scheduler.models import ScheduleProfile, ScheduleSlot


class ScheduleProfileForm(forms.ModelForm):
    class Meta:
        model = ScheduleProfile
        fields = ['name']
        labels = {
            'name': _('Profile Name'),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            Div(
                'name',
                css_class='col-12'
            )
        )


def _time_to_minutes(t: time) -> int:
    return t.hour * 60 + t.minute


def _slot_to_week_intervals(start_weekday: int, start_time: time, end_weekday: int, end_time: time):
    week_minutes = 7 * 24 * 60
    start = start_weekday * 1440 + _time_to_minutes(start_time)
    end = end_weekday * 1440 + _time_to_minutes(end_time)

    if start == end:
        return [(0, week_minutes)]

    if end < start:
        return [(start, week_minutes), (0, end)]

    return [(start, end)]


def _intervals_overlap(a_start, a_end, b_start, b_end) -> bool:
    return a_start < b_end and b_start < a_end


def _circular_gap(a_start, a_end, b_start, b_end, week_minutes):
    if a_start < b_end and b_start < a_end:
        return 0

    gaps = [
        (b_start - a_end) % week_minutes,
        (a_start - b_end) % week_minutes,
    ]
    return min(gaps)


class ScheduleSlotForm(forms.ModelForm):
    class Meta:
        model = ScheduleSlot
        fields = ['start_weekday', 'start_time', 'end_weekday', 'end_time']
        widgets = {
            'start_time': forms.TimeInput(attrs={'type': 'time'}),
            'end_time': forms.TimeInput(attrs={'type': 'time'}),
        }
        labels = {
            'start_weekday': _('Start Day'),
            'start_time': _('Start Time'),
            'end_weekday': _('End Day'),
            'end_time': _('End Time'),
        }

    def __init__(self, *args, **kwargs):
        self.profile = kwargs.pop("profile", None)
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)

        if self.profile is None and getattr(self.instance, "profile_id", None):
            self.profile = self.instance.profile

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('start_weekday', css_class='col-md-6'),
                Div('start_time', css_class='col-md-6'),
                css_class='row'
            ),
            Div(
                Div('end_weekday', css_class='col-md-6'),
                Div('end_time', css_class='col-md-6'),
                css_class='row'
            ),
            Div(
                Div(
                    Submit('submit', _('Save'), css_class='btn btn-primary'),
                    HTML(f'<a href="{cancel_url}" class="btn btn-secondary">{_("Cancel")}</a>'),
                    css_class='col-12 d-flex justify-content-end gap-2 mt-3'
                ),
                css_class='row'
            )
        )

    def clean(self):
        cleaned = super().clean()
        week_minutes = 7 * 24 * 60
        start_weekday = cleaned.get("start_weekday")
        start_time = cleaned.get("start_time")
        end_weekday = cleaned.get("end_weekday")
        end_time = cleaned.get("end_time")

        if None in (start_weekday, start_time, end_weekday, end_time):
            return cleaned

        if self.profile is None:
            raise ValidationError(_("Unable to validate overlaps: schedule profile is missing."))

        new_intervals = _slot_to_week_intervals(start_weekday, start_time, end_weekday, end_time)

        total_minutes = sum((end - start) for start, end in new_intervals)

        if total_minutes < 10:
            raise ValidationError(_("The minimum duration between start and end must be at least 10 minutes."))

        if total_minutes > (week_minutes - 10):
            raise ValidationError(_("The minimum duration between start and end must be at least 10 minutes."))

        qs = ScheduleSlot.objects.filter(profile=self.profile)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)

        for existing in qs:
            existing_intervals = _slot_to_week_intervals(
                existing.start_weekday,
                existing.start_time,
                existing.end_weekday,
                existing.end_time,
            )

            for ns, ne in new_intervals:
                for es, ee in existing_intervals:
                    if _intervals_overlap(ns, ne, es, ee):
                        raise ValidationError(
                            _("This time slot overlaps with an existing slot (%(start)s → %(end)s)."),
                            params={
                                "start": f"{existing.get_start_weekday_display()} {existing.start_time.strftime('%H:%M')}",
                                "end": f"{existing.get_end_weekday_display()} {existing.end_time.strftime('%H:%M')}",
                            },
                        )

                    gap = _circular_gap(ns, ne, es, ee, week_minutes)
                    if gap < 10:
                        raise ValidationError(
                            _("There must be at least 10 minutes between time slots.")
                        )

        return cleaned