import ipaddress

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
            self.fields['wireguard_instance'].disabled = True
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
        route_type = cleaned_data.get('route_type')
        custom_routes_raw = (cleaned_data.get('custom_routes') or "")

        lines = [ln.strip() for ln in custom_routes_raw.splitlines() if ln.strip()]

        if route_type == 'default':
            if lines:
                self.add_error(
                    'custom_routes',
                    _("Custom routes should be empty when Route Type is 'Default Route'.")
                )
            if allow_custom:
                self.add_error(
                    'allow_peer_custom_routes',
                    _("Allowing peer custom routes is not applicable when Route Type is 'Default Route'.")
                )
            return cleaned_data

        if route_type == 'custom' and not lines:
            self.add_error(
                'custom_routes',
                _("At least one route must be provided when Route Type is 'Custom'.")
            )
            return cleaned_data

        if lines:
            validated_routes = []
            for line in lines:
                # exige ip/mask
                if "/" not in line:
                    self.add_error(
                        'custom_routes',
                        _("Invalid route format: '%(line)s'. Please use CIDR notation (e.g., 10.0.0.0/24).") % {
                            'line': line}
                    )
                    break

                try:
                    network = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    self.add_error(
                        'custom_routes',
                        _("Invalid route format: '%(line)s'. Please use CIDR notation (e.g., 10.0.0.0/24).") % {
                            'line': line}
                    )
                    break

                if str(network) in ('0.0.0.0/0', '::/0'):
                    self.add_error(
                        'custom_routes',
                        _("The route %(route)s is not allowed. Use the 'Default Route' type instead.") % {
                            'route': str(network)}
                    )
                    break

                if str(network) != line:
                    self.add_error(
                        'custom_routes',
                        _("'%(line)s' is not a network address. Use the network address (e.g., '%(net)s').") % {
                            'line': line,
                            'net': str(network),
                        }
                    )
                    break

                validated_routes.append(str(network))

            if not self.errors.get('custom_routes'):
                cleaned_data['custom_routes'] = '\n'.join(validated_routes)

        return cleaned_data

