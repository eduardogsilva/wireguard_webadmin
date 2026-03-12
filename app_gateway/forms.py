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
        fields = ['name', 'display_name', 'upstream']
        labels = {
            'name': _('Name'),
            'display_name': _('Display Name'),
            'upstream': _('Upstream'),
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

    def clean(self):
        cleaned_data = super().clean()
        upstream = (cleaned_data.get("upstream") or "").strip()

        if upstream:
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
        fields = ['application', 'hostname']
        labels = {
            'application': _('Application'),
            'hostname': _('Hostname'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('application', css_class='col-md-6'),
                Div('hostname', css_class='col-md-6'),
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
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('name', css_class='col-md-6'),
                Div('policy_type', css_class='col-md-6'),
                css_class='row'
            ),
            Div(
                Div('groups', css_class='col-md-6'),
                Div('methods', css_class='col-md-6'),
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


class ApplicationPolicyForm(forms.ModelForm):
    class Meta:
        model = ApplicationPolicy
        fields = ['application', 'default_policy']
        labels = {
            'application': _('Application'),
            'default_policy': _('Default Policy'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('application', css_class='col-md-6'),
                Div('default_policy', css_class='col-md-6'),
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


class ApplicationRouteForm(forms.ModelForm):
    class Meta:
        model = ApplicationRoute
        fields = ['application', 'name', 'path_prefix', 'policy', 'order']
        labels = {
            'application': _('Application'),
            'name': _('Route Name'),
            'path_prefix': _('Path Prefix'),
            'policy': _('Policy'),
            'order': _('Priority Order'),
        }

    def __init__(self, *args, **kwargs):
        cancel_url = kwargs.pop('cancel_url', '#')
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Div(
                Div('application', css_class='col-md-6'),
                Div('name', css_class='col-md-6'),
                css_class='row'
            ),
            Div(
                Div('path_prefix', css_class='col-md-8'),
                Div('order', css_class='col-md-4'),
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
                    css_class='col-12 d-flex justify-content-end gap-2 mt-3'
                ),
                css_class='row'
            )
        )
