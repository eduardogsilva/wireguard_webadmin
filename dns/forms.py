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
        hostname = self.cleaned_data.get('hostname')
        if hostname:
            regex = r'^[a-zA-Z][a-zA-Z0-9-\.]*[a-zA-Z0-9]$'
            if not re.match(regex, hostname):
                raise ValidationError('Invalid hostname')
        return
