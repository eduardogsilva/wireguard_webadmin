import uuid as uuid_lib

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _

from user_manager.models import UserAcl
from .forms import ApiKeyForm
from .models import ApiKey


@login_required
def view_api_key_list(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    page_title = _('API Keys')
    api_keys = ApiKey.objects.all().order_by('name')
    context = {'page_title': page_title, 'api_keys': api_keys}
    return render(request, 'api_v2/list.html', context)

@login_required
def view_manage_api_key(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    api_key = None
    if 'uuid' in request.GET:
        api_key = get_object_or_404(ApiKey, uuid=request.GET['uuid'])
        page_title = _('Edit API Key: ') + api_key.name
        
    else:
        page_title = _('Add API Key')

    if request.method == 'POST':
        if api_key:
            form = ApiKeyForm(request.POST, instance=api_key, user=request.user)
        else:
            form = ApiKeyForm(request.POST, user=request.user)

        if request.POST.get('regenerate_token') == 'true' and api_key:
            api_key.token = uuid_lib.uuid4()
            api_key.save()
            messages.success(request, _('Token regenerated successfully.'))
            return redirect('/manage_api/v2/list/')

        if form.is_valid():
            form.save()
            messages.success(request, _('API Key saved successfully.'))
            return redirect('/manage_api/v2/list/')
    else:
        if api_key:
            form = ApiKeyForm(instance=api_key, user=request.user)
        else:
            form = ApiKeyForm(user=request.user)

    form_description = {
        'size': '',
        'content': _('''
        <h5>API Keys</h5>
        <p>API Keys allow external applications to interact with the WireGuard WebAdmin API.</p>
        <p><strong>Token:</strong> The secret token used for authentication. Keep this secure.</p>
        <p><strong>Allowed Instances:</strong> The WireGuard instances this key can manage. If none are selected, the key has access to ALL instances.</p>
        <p><strong>Permissions:</strong> specific actions allowed for this key.</p>
        ''')
    }

    context = {
        'page_title': page_title,
        'form': form,
        'instance': api_key,
        'form_description': form_description
    }
    return render(request, 'api_v2/api_key_form.html', context)


@login_required
def view_delete_api_key(request, uuid):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    api_key = get_object_or_404(ApiKey, uuid=uuid)

    if request.method == 'POST':
        api_key.delete()
        messages.success(request, _('API Key deleted successfully.'))
        return redirect('api_v2_list')

    context = {
        'object': api_key,
        'title': _('Delete API Key'),
        'cancel_url': f"/manage_api/v2/manage/?uuid={api_key.uuid}",
        'text': _('Are you sure you want to delete the API Key "%(name)s"?') % {'name': api_key.name}
    }
    return render(request, 'generic_delete_confirmation.html', context)
