import re
from urllib.parse import urlparse

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, HTML, Div
from django import forms
from django.conf import settings
from django.utils.translation import gettext_lazy as _

from app_gateway.dns_providers import DNS_PROVIDERS
from app_gateway.models import (
    Application, ApplicationHost, AccessPolicy, ApplicationPolicy, ApplicationRoute, DnsChallengeCredential
)
from app_gateway.setup_defaults import is_ip_address


class ApplicationForm(forms.ModelForm):
    class Meta:
        model = Application
        fields = ['display_name', 'upstream', 'allow_invalid_cert']
        labels = {
            'display_name': _('Name'),
            'upstream': _('Upstream'),
            'allow_invalid_cert': _('Allow invalid/self-signed certificate'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)
        self.fields['display_name'].required = True

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('display_name', css_class='col-md-12'),
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
        upstream = (cleaned_data.get("upstream") or "").strip()

        if upstream:
            if "wireguard-webadmin:8000" in upstream:
                self.add_error("upstream", _("This upstream is reserved by the system."))

            if " " in upstream:
                self.add_error("upstream", _("Upstream URL cannot contain spaces."))

            parsed = urlparse(upstream)
            is_valid = (parsed.scheme in {"http", "https"} and bool(parsed.netloc))

            if not is_valid:
                self.add_error("upstream", _("Enter a valid upstream URL starting with http:// or https://"))
            elif parsed.path not in ("", "/") or parsed.query or parsed.fragment:
                self.add_error("upstream", _("Upstream must be a bare host address with no path, query or fragment. Use http://host or http://host:port"))
            elif parsed.scheme == "http" and cleaned_data.get("allow_invalid_cert"):
                self.add_error("allow_invalid_cert", _("This option is only available for https:// upstreams."))

        return cleaned_data


class ApplicationHostForm(forms.ModelForm):
    class Meta:
        model = ApplicationHost
        fields = ['hostname', 'certificate_type', 'dns_credential']
        labels = {
            'hostname': _('Hostname'),
            'certificate_type': _('Certificate'),
            'dns_credential': _('DNS Credential'),
        }

    def clean(self):
        cleaned_data = super().clean()
        hostname = (cleaned_data.get('hostname') or '').strip()
        certificate_type = cleaned_data.get('certificate_type')
        dns_credential = cleaned_data.get('dns_credential')

        if hostname and not self.is_reserved:
            if any(c in hostname for c in ('{', '}', '\n', '\r', '\x00', ' ')):
                self.add_error('hostname', _('Hostname contains invalid characters.'))

            webadmin_hostnames = [host.lower() for host in settings.ALLOWED_HOSTS]
            if hostname.lower() in webadmin_hostnames:
                self.add_error('hostname', _('This hostname is already used by WireGuard WebAdmin.'))

        if hostname and is_ip_address(hostname) and certificate_type != 'self_signed':
            self.add_error('certificate_type', _('IP addresses can only use a self-signed certificate.'))

        if certificate_type == 'dns_challenge':
            if not dns_credential:
                self.add_error('dns_credential', _('Select a DNS credential to use the DNS challenge.'))
        else:
            cleaned_data['dns_credential'] = None

        return cleaned_data

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        self.is_reserved = kwargs.pop('is_reserved', False)
        super().__init__(*args, **kwargs)
        self.fields['dns_credential'].required = False
        if self.is_reserved:
            self.fields['hostname'].disabled = True

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('hostname', css_class='col-md-12'),
                css_class='row'
            ),
            Div(
                Div('certificate_type', css_class='col-xl-6'),
                Div('dns_credential', css_class='col-xl-6'),
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
        fields = ['display_name', 'policy_type', 'groups', 'methods']
        labels = {
            'display_name': _('Name'),
            'policy_type': _('Policy Type'),
            'groups': _('Allowed Groups'),
            'methods': _('Authentication Methods'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        policy_type = kwargs.pop('policy_type', None)
        super().__init__(*args, **kwargs)
        self.fields['display_name'].required = True

        if self.instance and self.instance.pk:
            policy_type = self.instance.policy_type

        if policy_type and not self.initial.get('policy_type'):
            self.initial['policy_type'] = policy_type

        self.fields['policy_type'].widget = forms.HiddenInput()

        self.helper = FormHelper()

        if policy_type in ['public', 'deny']:
            self.helper.layout = Layout(
                Div(
                    Div('display_name', css_class='col-md-12'),
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
                    Div('display_name', css_class='col-md-12'),
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
        fields = ['display_name', 'path_prefix', 'policy', 'order']
        labels = {
            'display_name': _('Route Name'),
            'path_prefix': _('Path Prefix'),
            'policy': _('Policy'),
            'order': _('Order'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)
        self.fields['display_name'].required = True

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('display_name', css_class='col-md-12'),
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

    # Reserved path prefixes that map to internal system routes
    _RESERVED_PREFIXES = ('/auth-gateway',)

    def clean(self):
        cleaned_data = super().clean()
        path_prefix = (cleaned_data.get('path_prefix') or '').strip()
        if path_prefix:
            if not path_prefix.startswith('/'):
                self.add_error('path_prefix', _('Path prefix must start with /.'))
            elif ' ' in path_prefix:
                self.add_error('path_prefix', _('Path prefix cannot contain spaces.'))
            elif any(c in path_prefix for c in ('{', '}', '\n', '\r', '\x00', '%')):
                self.add_error('path_prefix', _('Path prefix contains invalid characters.'))
            elif any(
                path_prefix == r or path_prefix.startswith(r + '/')
                for r in self._RESERVED_PREFIXES
            ):
                self.add_error('path_prefix', _('This path prefix is reserved by the system.'))
            else:
                cleaned_data['path_prefix'] = path_prefix
        return cleaned_data


class DnsChallengeCredentialForm(forms.ModelForm):
    class Meta:
        model = DnsChallengeCredential
        fields = ['display_name', 'provider']
        labels = {
            'display_name': _('Name'),
            'provider': _('Provider'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)
        self.fields['display_name'].required = True

        stored_credentials = self.instance.credentials if self.instance and self.instance.pk else {}
        provider_rows = []
        for provider, provider_data in DNS_PROVIDERS.items():
            provider_fields = []
            for provider_field in provider_data['fields']:
                field_name = self.credential_field_name(provider, provider_field['name'])
                stored_value = stored_credentials.get(provider_field['name'], '') if self.instance.provider == provider else ''
                if provider_field.get('secret'):
                    help_text = ''
                    if stored_value:
                        help_text = _('Leave blank to keep the current value (ending in %(suffix)s).') % {
                            'suffix': stored_value[-4:]
                        }
                    self.fields[field_name] = forms.CharField(
                        label=provider_field['label'], required=False, help_text=help_text,
                        widget=forms.PasswordInput(render_value=False),
                    )
                else:
                    self.fields[field_name] = forms.CharField(
                        label=provider_field['label'], required=False, initial=stored_value,
                    )
                provider_fields.append(Div(field_name, css_class='col-md-12'))
            provider_rows.append(Div(*provider_fields, css_class=f'row provider-group provider-{provider}'))

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('display_name', css_class='col-xl-6'),
                Div('provider', css_class='col-xl-6'),
                css_class='row'
            ),
            *provider_rows,
            Div(
                Div(
                    Submit('submit', _('Save'), css_class='btn btn-primary'),
                    HTML(f'<a href="{cancel_url}" class="btn btn-secondary">{_("Cancel")}</a>'),
                    css_class='col-md-12'
                ),
                css_class='row'
            )
        )

    @staticmethod
    def credential_field_name(provider, field_name):
        return f'{provider}_{field_name}'

    def clean(self):
        cleaned_data = super().clean()
        provider = cleaned_data.get('provider')
        if provider not in DNS_PROVIDERS:
            return cleaned_data

        stored_credentials = {}
        if self.instance and self.instance.pk and self.instance.provider == provider:
            stored_credentials = self.instance.credentials

        credentials = {}
        for provider_field in DNS_PROVIDERS[provider]['fields']:
            field_name = self.credential_field_name(provider, provider_field['name'])
            value = (cleaned_data.get(field_name) or '').strip()
            if not value and provider_field.get('secret'):
                value = stored_credentials.get(provider_field['name'], '')
            if not value:
                self.add_error(field_name, _('This field is required.'))
            elif any(c in value for c in ('\n', '\r', '\x00')):
                self.add_error(field_name, _('This field contains invalid characters.'))
            elif provider_field.get('pattern') and not re.match(provider_field['pattern'], value):
                self.add_error(field_name, _('The value does not match the expected format for this provider.'))
            credentials[provider_field['name']] = value

        self.instance.credentials = credentials
        return cleaned_data
