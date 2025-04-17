from crispy_forms.helper import FormHelper
from crispy_forms.layout import Column, HTML, Layout, Row, Submit
from django import forms
from django.conf import settings
from django.utils.translation import gettext_lazy as _


class LanguageForm(forms.Form):
    language = forms.ChoiceField(
        choices=settings.LANGUAGES,
        label=_("Language"),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Row(
                Column('language', css_class='col-md-6'),
            ),


            Submit('submit', _("Change Language"), css_class='btn btn-primary'),

            Row(
            Column(HTML(
                "<span class='small'>" + _("If you find any issues with the translation or would like to request a new language, please open an") + " <a href='https://github.com/eduardogsilva/wireguard_webadmin/issues' target='_blank'>issue</a>.</span>"),
                   css_class='col-md-12', style='padding-top: 32px;'),
        ),
        )