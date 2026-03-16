from urllib.parse import urlparse

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, HTML, Div
from django import forms
from django.utils.translation import gettext_lazy as _

from app_gateway.models import (
    Application, ApplicationHost, AccessPolicy, ApplicationPolicy, ApplicationRoute
)


class ApplicationForm(forms.ModelForm):
    class Meta:
        model = Application
        fields = ['name', 'display_name', 'upstream', 'allow_invalid_cert']
        labels = {
            'name': _('Name'),
            'display_name': _('Display Name'),
            'upstream': _('Upstream'),
            'allow_invalid_cert': _('Allow invalid/self-signed certificate'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('name', css_class='col-md-6'),
                Div('display_name', css_class='col-md-6'),
                css_class='row'
            ),
            Div(
                Div('upstream', css_class='col-md-12'),
                Div('allow_invalid_cert', css_class='col-md-12'),
                css_class='row'
            ),
            Div(
                Div(
                    Submit('submit', _('Save'), css_class='btn btn-primary'),
                    HTML(f'<a href="{cancel_url}" class="btn btn-secondary">{_("Cancel")}</a>'),
                    css_class='col-md-12'
                ),
                css_class='row'
            )
        )

    def clean(self):
        cleaned_data = super().clean()
        name = cleaned_data.get("name")
        upstream = (cleaned_data.get("upstream") or "").strip()

        if name == "wireguard_webadmin":
            self.add_error("name", _("This is a reserved system name."))

        if upstream:
            if "wireguard-webadmin:8000" in upstream:
                self.add_error("upstream", _("This upstream is reserved by the system."))

            if " " in upstream:
                self.add_error("upstream", _("Upstream URL cannot contain spaces."))

            parsed = urlparse(upstream)
            is_valid = (parsed.scheme in {"http", "https"} and bool(parsed.netloc))

            if not is_valid:
                self.add_error("upstream", _("Enter a valid upstream URL starting with http:// or https://"))

        return cleaned_data


class ApplicationHostForm(forms.ModelForm):
    class Meta:
        model = ApplicationHost
        fields = ['hostname']
        labels = {
            'hostname': _('Hostname'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('hostname', css_class='col-md-12'),
                css_class='row'
            ),
            Div(
                Div(
                    Submit('submit', _('Save'), css_class='btn btn-primary'),
                    HTML(f'<a href="{cancel_url}" class="btn btn-secondary">{_("Cancel")}</a>'),
                    css_class='col-md-12'
                ),
                css_class='row'
            )
        )


class AccessPolicyForm(forms.ModelForm):
    class Meta:
        model = AccessPolicy
        fields = ['name', 'policy_type', 'groups', 'methods']
        labels = {
            'name': _('Name'),
            'policy_type': _('Policy Type'),
            'groups': _('Allowed Groups'),
            'methods': _('Authentication Methods'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        policy_type = kwargs.pop('policy_type', None)
        super().__init__(*args, **kwargs)

        if self.instance and self.instance.pk:
            policy_type = self.instance.policy_type

        if policy_type and not self.initial.get('policy_type'):
            self.initial['policy_type'] = policy_type

        self.fields['policy_type'].widget = forms.HiddenInput()

        self.helper = FormHelper()
        
        if policy_type in ['public', 'deny']:
            self.helper.layout = Layout(
                Div(
                    Div('name', css_class='col-md-12'),
                    'policy_type',
                    css_class='row'
                ),
                Div(
                    Div(
                        Submit('submit', _('Save'), css_class='btn btn-primary'),
                        HTML(f'<a href="{cancel_url}" class="btn btn-secondary">{_("Cancel")}</a>'),
                        css_class='col-md-12'
                    ),
                    css_class='row'
                )
            )
        else:
            self.helper.layout = Layout(
                Div(
                    Div('name', css_class='col-md-12'),
                    'policy_type',
                    css_class='row'
                ),
                Div(Div('methods', css_class='col-md-12'), css_class='row'),
                Div(Div('groups', css_class='col-md-12'), css_class='row'),
                Div(
                    Div(
                        Submit('submit', _('Save'), css_class='btn btn-primary'),
                        HTML(f'<a href="{cancel_url}" class="btn btn-secondary">{_("Cancel")}</a>'),
                        css_class='col-md-12'
                    ),
                    css_class='row'
                )
            )

    def clean(self):
        cleaned_data = super().clean()
        policy_type = cleaned_data.get('policy_type')
        groups = cleaned_data.get('groups')
        methods = cleaned_data.get('methods')

        if policy_type == 'protected':
            has_local_password = False
            local_password_count = 0
            oidc_count = 0
            totp_count = 0
            has_groups = groups and len(groups) > 0

            # Count authentication methods
            if methods:
                for method in methods:
                    if method.auth_type == 'local_password':
                        has_local_password = True
                        local_password_count += 1
                    elif method.auth_type == 'oidc':
                        oidc_count += 1
                    elif method.auth_type == 'totp':
                        totp_count += 1

            # Rule: Cannot select more than one local password method
            if local_password_count > 1:
                self.add_error('methods', _("Cannot select more than one Local Password authentication method."))

            # Rule: Cannot select more than one oidc method
            if oidc_count > 1:
                self.add_error('methods', _("Cannot select more than one OpenID Connect (OIDC) authentication method."))

            # Rule: Cannot select more than one TOTP method
            if totp_count > 1:
                self.add_error('methods', _("Cannot select more than one TOTP authentication method."))

            # Rule: Cannot mix local password and oidc
            if local_password_count > 0 and oidc_count > 0:
                self.add_error('methods', _("Cannot select both Local Password and OpenID Connect (OIDC) authentication methods."))

            # Rule: TOTP cannot be selected alone — must be combined with local_password or oidc
            if totp_count > 0 and local_password_count == 0 and oidc_count == 0:
                self.add_error('methods', _("TOTP must be combined with a Local Password or OpenID Connect authentication method."))

            # Rule: If local password is selected, at least one user group must be selected
            if has_local_password and not has_groups:
                self.add_error('groups', _("At least one user group must be selected when using Local Password authentication."))

            # Rule: If local password is NOT selected, user groups cannot be selected
            if not has_local_password and has_groups:
                self.add_error('groups', _("User groups can only be used with Local Password authentication."))

        return cleaned_data


class ApplicationPolicyForm(forms.ModelForm):
    class Meta:
        model = ApplicationPolicy
        fields = ['default_policy']
        labels = {
            'default_policy': _('Default Policy'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('default_policy', css_class='col-md-12'),
                css_class='row'
            ),
            Div(
                Div(
                    Submit('submit', _('Save'), css_class='btn btn-primary'),
                    HTML(f'<a href="{cancel_url}" class="btn btn-secondary">{_("Cancel")}</a>'),
                    css_class='col-md-12'
                ),
                css_class='row'
            )
        )


class ApplicationRouteForm(forms.ModelForm):
    class Meta:
        model = ApplicationRoute
        fields = ['name', 'path_prefix', 'policy', 'order']
        labels = {
            'name': _('Route Name'),
            'path_prefix': _('Path Prefix'),
            'policy': _('Policy'),
            'order': _('Order'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('name', css_class='col-md-12'),
                css_class='row'
            ),
            Div(
                Div('path_prefix', css_class='col-xl-7'),
                Div('order', css_class='col-xl-5'),
                css_class='row'
            ),
            Div(
                Div('policy', css_class='col-md-12'),
                css_class='row'
            ),
            Div(
                Div(
                    Submit('submit', _('Save'), css_class='btn btn-primary'),
                    HTML(f'<a href="{cancel_url}" class="btn btn-secondary">{_("Cancel")}</a>'),
                    css_class='col-md-12'
                ),
                css_class='row'
            )
        )
