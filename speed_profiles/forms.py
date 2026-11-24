from crispy_forms.helper import FormHelper
from crispy_forms.layout import Button, Div, Layout, Submit
from django import forms
from django.utils.translation import gettext_lazy as _

from speed_profiles.models import SpeedProfile


class SpeedProfileForm(forms.ModelForm):
    class Meta:
        model = SpeedProfile
        fields = ['name', 'download_limit', 'download_burst', 'upload_limit', 'upload_burst']
        labels = {
            'name': _('Name'),
            'download_limit': _('Download (Mbit/s)'),
            'download_burst': _('Download burst (MB)'),
            'upload_limit': _('Upload (Mbit/s)'),
            'upload_burst': _('Upload burst (MB)'),
        }
        help_texts = {
            'download_limit': _('Traffic that reaches the peer. 0 disables the download limit.'),
            'upload_limit': _('Traffic that the peer sends. 0 disables the upload limit.'),
            'download_burst': _('Data that may pass at full speed before the limit applies. 0 disables the burst.'),
            'upload_burst': _('Data that may pass at full speed before the limit applies. 0 disables the burst.'),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ('download_limit', 'download_burst', 'upload_limit', 'upload_burst'):
            self.fields[field_name].widget.attrs.update({'min': '0', 'step': 'any'})
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Div('name', css_class='col-md-12'),
            Div(
                Div('download_limit', css_class='col-md-6'),
                Div('download_burst', css_class='col-md-6'),
                css_class='row',
            ),
            Div(
                Div('upload_limit', css_class='col-md-6'),
                Div('upload_burst', css_class='col-md-6'),
                css_class='row',
            ),
            Div(
                Submit('submit', _('Save'), css_class='btn btn-success'),
                Button('cancel', _('Back'), css_class='btn btn-secondary', onclick="window.location.href='/speed_profiles/'"),
                css_class='col-md-12',
            ),
        )

    def clean(self):
        cleaned_data = super().clean()
        for field_name in ('download_limit', 'download_burst', 'upload_limit', 'upload_burst'):
            value = cleaned_data.get(field_name)
            if value is not None and value < 0:
                self.add_error(field_name, _('Enter a value greater than or equal to zero.'))
        if self.errors:
            return cleaned_data

        if not cleaned_data.get('download_limit') and not cleaned_data.get('upload_limit'):
            raise forms.ValidationError(_('Set at least a download or an upload limit.'))
        if cleaned_data.get('download_burst') and not cleaned_data.get('download_limit'):
            self.add_error('download_burst', _('The burst requires a download limit.'))
        if cleaned_data.get('upload_burst') and not cleaned_data.get('upload_limit'):
            self.add_error('upload_burst', _('The burst requires an upload limit.'))
        return cleaned_data
