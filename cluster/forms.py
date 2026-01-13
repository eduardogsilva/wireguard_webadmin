from crispy_forms.helper import FormHelper
from crispy_forms.layout import Column, HTML, Layout, Row, Submit
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .models import ClusterSettings, Worker


class WorkerForm(forms.ModelForm):
    class Meta:
        model = Worker
        fields = ['name', 'enabled', 'ip_lock', 'ip_address', 'country', 'city', 'hostname', 'token']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['name'].label = _("Name")
        self.fields['enabled'].label = _("Enabled")
        self.fields['ip_lock'].label = _("IP Lock")
        self.fields['ip_address'].label = _("IP Address")
        self.fields['country'].label = _("Country")
        self.fields['city'].label = _("City")
        self.fields['hostname'].label = _("Hostname")
        self.fields['token'].label = _("Token")
        
        back_label = _("Back")
        delete_label = _("Delete")
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        
        if self.instance.pk:
            delete_html = f"<a href='javascript:void(0)' class='btn btn-outline-danger' data-command='delete' onclick='openCommandDialog(this)'>{delete_label}</a>"
        else:
            delete_html = ''
            
        self.helper.layout = Layout(
            Row(
                Column('name', css_class='form-group col-md-6 mb-0'),
                Column('hostname', css_class='form-group col-md-6 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('country', css_class='form-group col-md-6 mb-0'),
                Column('city', css_class='form-group col-md-6 mb-0'),

            ),
            Row(

                Column('token', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column(css_class='form-group col-md-6 mb-0'),
                Column('ip_address', css_class='form-group col-md-6 mb-0'),
                css_class='form-row'
            ),
            Row(

                Column('enabled', css_class='form-group col-md-6 mb-0'),
                Column('ip_lock', css_class='form-group col-md-6 mb-0'),

                css_class='form-row'
            ),
            Row(
                Column(
                    Submit('submit', _('Save'), css_class='btn btn-success'),
                    HTML(f' <a class="btn btn-secondary" href="/cluster/">{back_label}</a> '),
                    HTML(delete_html),
                    css_class='col-md-12'),
                css_class='form-row'
            )
        )

    def clean(self):
        cleaned_data = super().clean()
        name = cleaned_data.get('name')
        ip_lock = cleaned_data.get('ip_lock')
        ip_address = cleaned_data.get('ip_address')

        if Worker.objects.filter(name=name).exclude(pk=self.instance.pk if self.instance else None).exists():
            raise ValidationError(_("A worker with that name already exists."))

        if ip_lock and not ip_address:
            raise ValidationError(_("IP Address is required when IP Lock is enabled."))

        return cleaned_data


class ClusterSettingsForm(forms.ModelForm):
    class Meta:
        model = ClusterSettings
        fields = ['enabled', 'primary_enable_wireguard', 'cluster_mode', 'restart_mode', 'worker_display']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['enabled'].label = _("Cluster Enabled")
        self.fields['primary_enable_wireguard'].label = _("Primary Enable WireGuard")
        self.fields['cluster_mode'].label = _("Cluster Mode")
        self.fields['restart_mode'].label = _("Restart Mode")
        self.fields['worker_display'].label = _("Worker Display")

        back_label = _("Back")
        self.helper = FormHelper()
        self.helper.form_method = 'post'

        self.helper.layout = Layout(
            Row(
                Column('enabled', css_class='form-group col-md-6 mb-0'),
                Column('primary_enable_wireguard', css_class='form-group col-md-6 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('cluster_mode', css_class='form-group col-md-6 mb-0'),
                Column('restart_mode', css_class='form-group col-md-6 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('worker_display', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column(
                    Submit('submit', _('Save'), css_class='btn btn-success'),
                    HTML(f' <a class="btn btn-secondary" href="/cluster/">{back_label}</a> '),
                    css_class='col-md-12'),
                css_class='form-row'
            )
        )

    def clean(self):
        cleaned_data = super().clean()
        primary_enable_wireguard = cleaned_data.get('primary_enable_wireguard')
        cluster_enabled = cleaned_data.get('enabled')

        if cluster_enabled and not settings.WIREGUARD_STATUS_CACHE_ENABLED:
            raise ValidationError(_("Cluster mode requires WireGuard status cache to be enabled."))

        if not primary_enable_wireguard:
            raise ValidationError(_("Disabling WireGuard on the master server is currently not supported."))

        return cleaned_data