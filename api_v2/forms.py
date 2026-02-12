from crispy_forms.helper import FormHelper
from crispy_forms.layout import Column, HTML, Layout, Row, Submit
from django import forms
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from .models import ApiKey


class ApiKeyForm(forms.ModelForm):
    class Meta:
        model = ApiKey
        fields = [
            'name',
            'allowed_instances',
            #'allow_restart',
            #'allow_reload',
            #'allow_export',
            'enabled',
        ]

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.form_method = 'post'
        
        back_label = _("Back")
        delete_label = _("Delete")
        regenerate_label = _("Regenerate Token")

        if self.instance.pk:
            delete_url = reverse('api_v2_delete', kwargs={'uuid': self.instance.uuid})
            delete_html = f"<a href='{delete_url}' class='btn btn-outline-danger'>{delete_label}</a>"
            
            regenerate_html = f'<button type="submit" name="regenerate_token" value="true" class="btn btn-warning" onclick="return confirm(\'{_("Are you sure you want to regenerate the token? The old token will stop working immediately.")}\')">{regenerate_label}</button>'
        else:
            delete_html = ''
            regenerate_html = ''

        self.helper.layout = Layout(
            Row(
                Column('name', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('allowed_instances', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            #Row(
            #    Column('allow_restart', css_class='form-group col-md-4 mb-0'),
            #    Column('allow_reload', css_class='form-group col-md-4 mb-0'),
            #    Column('allow_export', css_class='form-group col-md-4 mb-0'),
            #    css_class='form-row'
            #),
             Row(
                Column('enabled', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column(
                    Submit('submit', _('Save'), css_class='btn btn-success'),
                    HTML(f' {regenerate_html} ') if regenerate_html else HTML(''),
                    HTML(f' <a class="btn btn-secondary" href="/manage_api/v2/list/">{back_label}</a> '),
                    HTML(f' {delete_html} '),
                    css_class='col-md-12'
                ),
                css_class='form-row'
            )
        )
