from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, HTML, Div
from django import forms
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
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)
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
