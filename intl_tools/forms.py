from crispy_forms.helper import FormHelper
from crispy_forms.layout import Column, Layout, Row, Submit
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
            Submit('submit', _("Change Language"), css_class='btn btn-primary')
        )