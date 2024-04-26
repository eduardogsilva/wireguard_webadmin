import requests
from .models import DNSSettings, StaticHost

from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Fieldset, ButtonHolder, Submit, Div, Field, HTML
from crispy_forms.bootstrap import FormActions, StrictButton
from django.core.exceptions import ValidationError
from datetime import datetime
from django.core.exceptions import ValidationError
import re


class DNSSettingsForm(forms.ModelForm):
    class Meta:
        model = DNSSettings
        fields = ['dns_primary', 'dns_secondary']

    def __init__(self, *args, **kwargs):
        super(DNSSettingsForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.fields['dns_primary'].label = 'Primary Resolver'
        self.fields['dns_secondary'].label = 'Secondary Resolver'
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Fieldset(
                'Resolver Settings',
                Div(
                    Field('dns_primary', css_class='form-control'),
                    Field('dns_secondary', css_class='form-control'),
                    css_class='col-md-6'
                ),
            ),
            FormActions(
                Submit('save', 'Save', css_class='btn btn-primary'),
                HTML('<a class="btn btn-outline-primary" href="/dns/">Back</a>'),
            )
        )

    def clean(self):
        cleaned_data = super().clean()
        dns_primary = cleaned_data.get('dns_primary')
        dns_secondary = cleaned_data.get('dns_secondary')
        if dns_secondary and not dns_primary:
            dns_primary = dns_secondary
            dns_secondary = ''
            cleaned_data['dns_primary'] = dns_primary
            cleaned_data['dns_secondary'] = dns_secondary
        if dns_primary and dns_primary == dns_secondary:
            raise ValidationError('Primary and secondary DNS cannot be the same')
        return


class StaticHostForm(forms.ModelForm):
    class Meta:
        model = StaticHost
        fields = ['hostname', 'ip_address']

    def __init__(self, *args, **kwargs):
        super(StaticHostForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        if self.instance.pk:
            delete_html = "<a href='javascript:void(0)' class='btn btn-outline-danger' data-command='delete' onclick='openCommandDialog(this)'>Delete</a>"
        else:
            delete_html = ''
        self.helper.layout = Layout(
            Fieldset(
                'Static DNS',
                Div(
                    Field('hostname', css_class='form-control'),
                    Field('ip_address', css_class='form-control'),
                    css_class='col-md-6'
                ),
            ),
            FormActions(
                Submit('save', 'Save', css_class='btn btn-primary'),
                HTML('<a class="btn btn-outline-primary" href="/dns/">Back</a> '),
                HTML(delete_html),
            )
        )

    def clean(self):
        cleaned_data = super().clean()
        hostname = cleaned_data.get('hostname')
        if hostname:
            regex = r'^[a-zA-Z][a-zA-Z0-9-\.]*[a-zA-Z0-9]$'
            if not re.match(regex, hostname):
                raise ValidationError('Invalid hostname')
        return
