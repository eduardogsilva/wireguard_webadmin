from django.conf import settings
from django.shortcuts import redirect, render
from django.utils import translation

from .forms import LanguageForm


def view_change_language(request):
    if request.method == 'POST':
        form = LanguageForm(request.POST)
        if form.is_valid():
            language = form.cleaned_data['language']
            translation.activate(language)
            request.session['django_language'] = language
            next_url = '/'
            response = redirect(next_url)
            response.set_cookie(settings.LANGUAGE_COOKIE_NAME, language)
            return response
    else:
        form = LanguageForm(initial={'language': translation.get_language()})

    if request.user.is_authenticated:
        return render(request, 'generic_form.html', {'form': form})
    else:
        return render(request, 'generic_form_guest.html', {'form': form})