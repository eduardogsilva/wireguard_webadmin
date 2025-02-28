from crispy_forms.templatetags.crispy_forms_field import css_class
from django import forms
from .models import InviteSettings
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Row, Column, Submit, HTML


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
        bool_choices = [(True, 'Enabled'), (False, 'Disabled')]
        bool_coerce = lambda x: True if x == 'True' else False

        # Override the five download_enabled fields to use a dropdown
        for field_name in [
            'download_1_enabled',
            'download_2_enabled',
            'download_3_enabled',
            'download_4_enabled',
            'download_5_enabled'
        ]:
            self.fields[field_name] = forms.TypedChoiceField(
                choices=bool_choices,
                coerce=bool_coerce,
                widget=forms.Select(),
                initial=self.instance.__dict__.get(field_name, True) if self.instance and self.instance.pk else True,
                label='Status'
            )
        self.fields['download_1_url'].label = 'URL'
        self.fields['download_2_url'].label = 'URL'
        self.fields['download_3_url'].label = 'URL'
        self.fields['download_4_url'].label = 'URL'
        self.fields['download_5_url'].label = 'URL'
        self.fields['download_1_label'].label = 'Text'
        self.fields['download_2_label'].label = 'Text'
        self.fields['download_3_label'].label = 'Text'
        self.fields['download_4_label'].label = 'Text'
        self.fields['download_5_label'].label = 'Text'
        self.fields['download_instructions'].label = 'Web Page Instructions'
        self.fields['invite_email_subject'].label = 'Email Subject'
        self.fields['invite_email_body'].label = 'Email Message'
        self.fields['invite_email_enabled'].label = 'Email Enabled'
        self.fields['invite_whatsapp_body'].label = 'WhatsApp Message'
        self.fields['invite_whatsapp_enabled'].label = 'WhatsApp Enabled'
        self.fields['invite_text_body'].label = 'Text Message'

        # Initialize Crispy Forms helper
        self.helper = FormHelper()
        self.helper.form_method = 'post'

        # Define form layout
        self.helper.layout = Layout(
            Row(
                Column(
                    HTML("<h3>General Settings</h3>"),
                    Row(
                        Column('invite_url', css_class='form-group col-md-6 mb-0'),
                        Column('required_user_level', css_class='form-group col-md-6 mb-0'),
                    ),
                    Row(
                        Column(css_class='form-group col-md-6 mb-0'),
                        Column(css_class='form-group col-md-6 mb-0'),
                    ),

                    Row(
                        Column('default_password', css_class='form-group col-md-4 mb-0'),
                        Column('enforce_random_password', css_class='form-group col-md-4 mb-0'),
                        css_class='form-row'
                    ),

                    Row(

                        Column('random_password_length', css_class='form-group col-md-4 mb-0'),
                        Column('random_password_complexity', css_class='form-group col-md-4 mb-0'),
                        css_class='form-row'
                    ),
                    Row(
                        Column('invite_expiration', css_class='form-group col-md-4 mb-0'),
                        css_class='form-row'
                    ),
                    HTML("<h3>Download Buttons</h3>"),
                    Row(
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

                    Row(
                        Column(
                            Submit('submit', 'Save', css_class='btn btn-success'),
                            HTML(' <a class="btn btn-secondary" href="/configurations/list/">Back</a> '),
                            css_class='col-md-12'
                        ),
                        css_class='form-row'
                    ),

                    css_class='col-xl-6'),

                Column(
                    HTML("<h3>Message templates</h3>"),
                    Column( css_class='form-group col-md-12 mb-0'),



                    Row(
                        Column('download_instructions', css_class='form-group col-md-12 mb-0'),
                        css_class='form-row'
                    ),
                    HTML("<hr>"),

                    Row(

                        Column(HTML("<h5>Email Message Template</h5>"), css_class='form-group col-md-12 mb-0'),
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
                        Column(HTML("<h5>WhatsApp Message Template</h5>"), css_class='form-group col-md-12 mb-0'),
                        Column('invite_whatsapp_body', css_class='form-group col-md-12 mb-0'),
                        Column('invite_whatsapp_enabled', css_class='form-group col-md-12 mb-0'),
                        css_class='form-row'
                    ),
                    HTML("<hr>"),
                    Row(

                        Column(HTML("<h5>Text Message Template</h5>"), css_class='form-group col-md-12 mb-0'),
                        Column('invite_text_body', css_class='form-group col-md-12 mb-0'),
                        css_class='form-row'
                    ),
                    css_class='col-xl-6'),


                css_class='row'),

        )
