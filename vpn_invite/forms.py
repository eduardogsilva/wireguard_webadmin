from crispy_forms.helper import FormHelper
from crispy_forms.layout import Column, HTML, Layout, Row, Submit
from django import forms
from django.utils.translation import gettext_lazy as _

from wireguard_tools.models import EmailSettings
from .models import InviteSettings


class InviteSettingsForm(forms.ModelForm):
    class Meta:
        model = InviteSettings
        fields = [
            'default_password',
            'enforce_random_password',
            'required_user_level',
            'random_password_length',
            'random_password_complexity',
            'invite_expiration',
            'download_1_label',
            'download_2_label',
            'download_3_label',
            'download_4_label',
            'download_5_label',
            'download_1_url',
            'download_2_url',
            'download_3_url',
            'download_4_url',
            'download_5_url',
            'download_1_enabled',
            'download_2_enabled',
            'download_3_enabled',
            'download_4_enabled',
            'download_5_enabled',
            'download_instructions',
            'invite_url',
            'invite_text_body',
            'invite_email_subject',
            'invite_email_body',
            'invite_email_enabled',
            'invite_whatsapp_body',
            'invite_whatsapp_enabled',
        ]

    def __init__(self, *args, **kwargs):
        super(InviteSettingsForm, self).__init__(*args, **kwargs)

        # Define boolean dropdown choices
        bool_choices = [(True, _('Enabled')), (False, _('Disabled'))]
        bool_coerce = lambda x: True if x == 'True' else False

        for field_name in [
            'download_1_enabled',
            'download_2_enabled',
            'download_3_enabled',
            'download_4_enabled',
            'download_5_enabled',
            'enforce_random_password',
        ]:
            self.fields[field_name] = forms.TypedChoiceField(
                choices=bool_choices,
                coerce=bool_coerce,
                widget=forms.Select(),
                required=False,
                initial=self.instance.__dict__.get(field_name, True) if self.instance and self.instance.pk else True,
            )

        self.fields['download_1_url'].label = _('URL')
        self.fields['download_2_url'].label = _('URL')
        self.fields['download_3_url'].label = _('URL')
        self.fields['download_4_url'].label = _('URL')
        self.fields['download_5_url'].label = _('URL')
        self.fields['download_1_label'].label = _('Text')
        self.fields['download_2_label'].label = _('Text')
        self.fields['download_3_label'].label = _('Text')
        self.fields['download_4_label'].label = _('Text')
        self.fields['download_5_label'].label = _('Text')
        self.fields['download_1_enabled'].label = _('Status')
        self.fields['download_2_enabled'].label = _('Status')
        self.fields['download_3_enabled'].label = _('Status')
        self.fields['download_4_enabled'].label = _('Status')
        self.fields['download_5_enabled'].label = _('Status')
        self.fields['download_instructions'].label = _('Web Page Instructions')
        self.fields['invite_email_subject'].label = _('Email Subject')
        self.fields['invite_email_body'].label = _('Email Message')
        self.fields['invite_email_enabled'].label = _('Email Enabled')
        self.fields['invite_whatsapp_body'].label = _('WhatsApp Message')
        self.fields['invite_whatsapp_enabled'].label = _('WhatsApp Enabled')
        self.fields['invite_text_body'].label = _('Text Message')
        self.fields['invite_expiration'].label = _('Expiration (minutes)')
        self.fields['enforce_random_password'].label = _('Random Password')
        self.fields['invite_url'].label = _('Invite URL')
        self.fields['required_user_level'].label = _('Required User Level')
        self.fields['default_password'].label = _('Default Password')
        self.fields['random_password_length'].label = _('Random Password Length')
        self.fields['random_password_complexity'].label = _('Random Password Complexity')
        self.helper = FormHelper()
        self.helper.form_method = 'post'

        self.helper.layout = Layout(
            Row(
                Column(
                    HTML("<h3>" + _("General Settings") + "</h3>"),
                    Row(
                        Column('invite_url', css_class='form-group col-md-12 mb-0'),
                    ),
                    Row(
                        Column('required_user_level', css_class='form-group col-md-6 mb-0'),
                        Column('invite_expiration', css_class='form-group col-md-6 mb-0'),
                    ),
                    HTML('<hr>'),
                    Row(
                        Column(HTML("<h5>User Authentication</h5>"), css_class='form-group col-md-12 mb-0'),
                        Column('enforce_random_password', css_class='form-group col-md-6 mb-0'),
                        Column('default_password', css_class='form-group col-md-6 mb-0'),
                        css_class='form-row'
                    ),
                    Row(
                        Column('random_password_length', css_class='form-group col-md-6 mb-0'),
                        Column('random_password_complexity', css_class='form-group col-md-6 mb-0'),
                        css_class='form-row'
                    ),
                    HTML("<hr>"),
                    Row(
                        Column(HTML("<h5>" + _("Download Buttons") + "</h5>"), css_class='form-group col-md-12 mb-0'),
                        Column('download_1_label', css_class='form-group col-md-3 mb-0'),
                        Column('download_1_url', css_class='form-group col-md-6 mb-0'),
                        Column('download_1_enabled', css_class='form-group col-md-3 mb-0'),
                        css_class='form-row'
                    ),
                    Row(
                        Column('download_2_label', css_class='form-group col-md-3 mb-0'),
                        Column('download_2_url', css_class='form-group col-md-6 mb-0'),
                        Column('download_2_enabled', css_class='form-group col-md-3 mb-0'),
                        css_class='form-row'
                    ),
                    Row(
                        Column('download_3_label', css_class='form-group col-md-3 mb-0'),
                        Column('download_3_url', css_class='form-group col-md-6 mb-0'),
                        Column('download_3_enabled', css_class='form-group col-md-3 mb-0'),
                        css_class='form-row'
                    ),
                    Row(
                        Column('download_4_label', css_class='form-group col-md-3 mb-0'),
                        Column('download_4_url', css_class='form-group col-md-6 mb-0'),
                        Column('download_4_enabled', css_class='form-group col-md-3 mb-0'),
                        css_class='form-row'
                    ),
                    Row(
                        Column('download_5_label', css_class='form-group col-md-3 mb-0'),
                        Column('download_5_url', css_class='form-group col-md-6 mb-0'),
                        Column('download_5_enabled', css_class='form-group col-md-3 mb-0'),
                        css_class='form-row'
                    ),

                    css_class='col-xl-12'),
                Column(
                    HTML("<h3>" + _('Message templates') + "</h3>"),
                    Row(
                        Column('download_instructions', css_class='form-group col-md-12 mb-0'),
                        css_class='form-row'
                    ),
                    HTML("<hr>"),
                    Row(
                        Column(HTML("<h5>" + _("Email Message Template") + "</h5>"), css_class='form-group col-md-12 mb-0'),
                        Column('invite_email_subject', css_class='form-group col-md-12 mb-0'),
                        Column('invite_email_body', css_class='form-group col-md-12 mb-0'),
                        css_class='form-row'
                    ),
                    Row(
                        Column('invite_email_enabled', css_class='form-group col-md-6 mb-0'),
                        css_class='form-row'
                    ),
                    HTML("<hr>"),
                    Row(
                        Column(HTML("<h5>" + _("WhatsApp Message Template") + "</h5>"), css_class='form-group col-md-12 mb-0'),
                        Column('invite_whatsapp_body', css_class='form-group col-md-12 mb-0'),
                        Column('invite_whatsapp_enabled', css_class='form-group col-md-12 mb-0'),
                        css_class='form-row'
                    ),
                    HTML("<hr>"),
                    Row(
                        Column(HTML("<h5>" + _("Text Message Template") + "</h5>"), css_class='form-group col-md-12 mb-0'),
                        Column('invite_text_body', css_class='form-group col-md-12 mb-0'),
                        css_class='form-row'
                    ),
                    css_class='col-xl-12'),
                css_class='row'),
            Row(
                Column(
                    Submit('submit', _('Save'), css_class='btn btn-success'),
                    HTML(' <a class="btn btn-secondary" href="/vpn_invite/">' + _('Back') + '</a> '),
                    css_class='col-md-12'
                ),
                css_class='form-row'),
        )

    def clean(self):
        cleaned_data = super().clean()

        # Validate invite_url: it must start with 'https://' and end with '/invite/'
        invite_url = cleaned_data.get('invite_url')
        if invite_url:
            if not invite_url.startswith("https://"):
                self.add_error('invite_url', _("Invite URL must start with 'https://'."))
            if not invite_url.endswith("/invite/"):
                self.add_error('invite_url', _("Invite URL must end with '/invite/'."))

        # Validate invite_expiration: must be between 1 and 1440 minutes
        invite_expiration = cleaned_data.get('invite_expiration')
        if invite_expiration is not None:
            if invite_expiration < 1 or invite_expiration > 1440:
                self.add_error('invite_expiration', _("Expiration (minutes) must be between 1 and 1440."))

        # Validate default_password based on enforce_random_password flag
        default_password = cleaned_data.get('default_password', '')
        enforce_random_password = cleaned_data.get('enforce_random_password')
        random_password_length = cleaned_data.get('random_password_length')
        if enforce_random_password is True:
            if default_password:
                self.add_error('default_password',
                               _("Default password must not be provided when random password is enabled."))
            if random_password_length < 6:
                self.add_error('random_password_length', _("Random password length must be at least 6 characters."))
        else:
            # When random password is disabled, default password must be provided and have at least 6 characters.
            if not default_password:
                self.add_error('default_password',
                               _("Default password must be provided when random password is disabled."))
            elif len(default_password) < 6:
                self.add_error('default_password', _("Default password must be at least 6 characters long."))

        # Validate download buttons: if enabled, the respective text and url fields must not be blank.
        for i in range(1, 6):
            enabled = cleaned_data.get(f'download_{i}_enabled')
            label = (cleaned_data.get(f'download_{i}_label') or '').strip()
            url = (cleaned_data.get(f'download_{i}_url') or '').strip()
            if enabled:
                if not label:
                    self.add_error(f'download_{i}_label',
                                   _("Text field must not be empty when download button is enabled."))
                if not url:
                    self.add_error(f'download_{i}_url', _("URL field must not be empty when download button is enabled."))

        # Validate that default_password is not contained in any message templates or the subject
        message_fields = ['invite_text_body', 'invite_email_subject', 'invite_email_body', 'invite_whatsapp_body']
        if default_password:
            for field in message_fields:
                content = cleaned_data.get(field, '')
                if default_password in content:
                    self.add_error('default_password',
                                   _("Default password must not be contained in any message template. Found at: ") + f"{field.replace('_', ' ')}.")

        # Validate that all message templates include the placeholder '{invite_url}'
        for field in message_fields:
            if field != 'invite_email_subject':
                content = cleaned_data.get(field, '')
                if '{invite_url}' not in content:
                    self.add_error(field, _("The template must include the placeholder '{invite_url}'."))

        return cleaned_data


class EmailSettingsForm(forms.ModelForm):
    class Meta:
        model = EmailSettings
        fields = [
            'smtp_username',
            'smtp_password',
            'smtp_host',
            'smtp_port',
            'smtp_encryption',
            'smtp_from_address',
            'enabled',
        ]

    def __init__(self, *args, **kwargs):
        super(EmailSettingsForm, self).__init__(*args, **kwargs)

        # Set custom labels for form fields
        self.fields['smtp_username'].label = _('Username')
        self.fields['smtp_password'].label = _('Password')
        self.fields['smtp_host'].label = _('Host')
        self.fields['smtp_port'].label = _('Port')
        self.fields['smtp_encryption'].label = _('Encryption')
        self.fields['smtp_from_address'].label = _('From Address')

        self.fields['smtp_password'].required = True
        self.fields['smtp_host'].required = True
        self.fields['smtp_port'].required = True
        self.fields['smtp_encryption'].required = True
        self.fields['smtp_from_address'].required = True
        self.fields['smtp_username'].required = True
        self.fields['enabled'].label = _('Enabled')

        # Use PasswordInput widget to hide the password
        self.fields['smtp_password'].widget = forms.PasswordInput(render_value=False)

        # Ensure that during edit the saved password is not displayed
        if self.instance and self.instance.pk:
            self.fields['smtp_password'].initial = ''

        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            HTML("<h3>SMTP Settings</h3>"),
            Row(
                Column('smtp_username', css_class='form-group col-md-4 mb-0'),
                Column('smtp_password', css_class='form-group col-md-4 mb-0'),
                Column('smtp_from_address', css_class='form-group col-md-4 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('smtp_host', css_class='form-group col-md-4 mb-0'),
                Column('smtp_port', css_class='form-group col-md-4 mb-0'),
                Column('smtp_encryption', css_class='form-group col-md-4 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column('enabled', css_class='form-group col-md-4 mb-0'),
                css_class='form-row'
            ),
            Row(
                Column(
                    Submit('submit', _('Save'), css_class='btn btn-success'),
                    HTML(' <a class="btn btn-secondary" href="/vpn_invite/">' + _('Back') + '</a> '),
                    css_class='col-md-12'
                ),
                css_class='form-row'
            )
        )

    def clean(self):
        cleaned_data = super().clean()
        smtp_port = cleaned_data.get('smtp_port')
        if smtp_port is not None and smtp_port <= 0:
            self.add_error('smtp_port', _("SMTP port must be between 1 and 65535."))

        return cleaned_data

