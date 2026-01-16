from crispy_forms.helper import FormHelper
from crispy_forms.layout import Column, HTML, Layout, Row, Submit
from django import forms
from django.utils.translation import gettext_lazy as _

from .models import RoutingTemplate


class RoutingTemplateForm(forms.ModelForm):
    class Meta:
        model = RoutingTemplate
        fields = [
            'name',
            'wireguard_instance',
            'default_template',
            'route_type',
            'custom_routes',
            'allow_peer_custom_routes',
            'enforce_route_policy',
        ]

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        self.fields['name'].label = _("Name")
        self.fields['wireguard_instance'].label = _("WireGuard Instance")
        self.fields['default_template'].label = _("Default Template")
        self.fields['route_type'].label = _("Route Type")
        self.fields['custom_routes'].label = _("Custom Routes")
        self.fields['allow_peer_custom_routes'].label = _("Allow Peer Custom Routes")
        self.fields['enforce_route_policy'].label = _("Enforce Route Policy")

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
                Column('wireguard_instance', css_class='form-group col-md-6 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('route_type', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
             Row(
                Column('custom_routes', css_class='form-group col-md-12 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('default_template', css_class='form-group col-md-12 mb-0'),
                Column('enforce_route_policy', css_class='form-group col-md-12 mb-0'),
                Column('allow_peer_custom_routes', css_class='form-group col-md-12 mb-0'),

                css_class='form-row'
            ),
            Row(
                Column(
                    Submit('submit', _('Save'), css_class='btn btn-success'),
                    HTML(f' <a class="btn btn-secondary" href="/routing-templates/list/">{back_label}</a> '),
                    HTML(delete_html),
                    css_class='col-md-12'),
                css_class='form-row'
            )
        )

    def clean(self):
        cleaned_data = super().clean()
        allow_custom = cleaned_data.get('allow_peer_custom_routes')
        enforce_policy = cleaned_data.get('enforce_route_policy')

        if allow_custom and enforce_policy:
            raise forms.ValidationError(_("You cannot enable 'Enforce Route Policy' when 'Allow Peer Custom Routes' is checked."))
        return cleaned_data
