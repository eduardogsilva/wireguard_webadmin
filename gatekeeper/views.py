from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.utils.translation import gettext as _

from gatekeeper.forms import GatekeeperUserForm, GatekeeperGroupForm, AuthMethodForm, AuthMethodAllowedDomainForm, \
    AuthMethodAllowedEmailForm
from gatekeeper.models import GatekeeperUser, GatekeeperGroup, AuthMethod, AuthMethodAllowedDomain, \
    AuthMethodAllowedEmail
from user_manager.models import UserAcl


@login_required
def view_gatekeeper_list(request):
    """Main list view containing tabs for Users, Groups, and Auth Methods"""
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=20).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})
    
    users = GatekeeperUser.objects.all().order_by('username')
    groups = GatekeeperGroup.objects.all().order_by('name')
    auth_methods = AuthMethod.objects.all().order_by('name')
    auth_domains = AuthMethodAllowedDomain.objects.all().order_by('domain')
    auth_emails = AuthMethodAllowedEmail.objects.all().order_by('email')
    
    tab = request.GET.get('tab', 'users')
    
    context = {
        'users': users,
        'groups': groups,
        'auth_methods': auth_methods,
        'auth_domains': auth_domains,
        'auth_emails': auth_emails,
        'active_tab': tab,
    }
    return render(request, 'gatekeeper/gatekeeper_list.html', context)


@login_required
def view_manage_gatekeeper_user(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    obj_uuid = request.GET.get('uuid')
    
    if obj_uuid:
        obj = get_object_or_404(GatekeeperUser, uuid=obj_uuid)
        title = _('Edit Gatekeeper User')
    else:
        obj = None
        title = _('Create Gatekeeper User')

    cancel_url = reverse('gatekeeper_list') + '?tab=users'

    if request.method == 'POST':
        form = GatekeeperUserForm(request.POST, instance=obj, cancel_url=cancel_url)
        if form.is_valid():
            form.save()
            messages.success(request, _('Gatekeeper User saved successfully.'))
            return redirect(cancel_url)
    else:
        form = GatekeeperUserForm(instance=obj, cancel_url=cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_gatekeeper_user(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    obj_uuid = request.GET.get('uuid')
    obj = get_object_or_404(GatekeeperUser, uuid=obj_uuid)
    
    cancel_url = reverse('gatekeeper_list') + '?tab=users'

    if request.method == 'POST':
        obj.delete()
        messages.success(request, _('Gatekeeper User deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'object': obj,
        'title': _('Delete Gatekeeper User'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the user "%(username)s"?') % {'username': obj.username}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_gatekeeper_group(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    obj_uuid = request.GET.get('uuid')
    
    if obj_uuid:
        obj = get_object_or_404(GatekeeperGroup, uuid=obj_uuid)
        title = _('Edit Gatekeeper Group')
    else:
        obj = None
        title = _('Create Gatekeeper Group')

    cancel_url = reverse('gatekeeper_list') + '?tab=groups'

    if request.method == 'POST':
        form = GatekeeperGroupForm(request.POST, instance=obj, cancel_url=cancel_url)
        if form.is_valid():
            form.save()
            messages.success(request, _('Gatekeeper Group saved successfully.'))
            return redirect(cancel_url)
    else:
        form = GatekeeperGroupForm(instance=obj, cancel_url=cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_gatekeeper_group(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    obj_uuid = request.GET.get('uuid')
    obj = get_object_or_404(GatekeeperGroup, uuid=obj_uuid)
    
    cancel_url = reverse('gatekeeper_list') + '?tab=groups'

    if request.method == 'POST':
        obj.delete()
        messages.success(request, _('Gatekeeper Group deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'object': obj,
        'title': _('Delete Gatekeeper Group'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the group "%(name)s"?') % {'name': obj.name}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_auth_method(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    obj_uuid = request.GET.get('uuid')
    
    if obj_uuid:
        obj = get_object_or_404(AuthMethod, uuid=obj_uuid)
        title = _('Edit Authentication Method')
    else:
        obj = None
        title = _('Create Authentication Method')

    cancel_url = reverse('gatekeeper_list') + '?tab=auth_methods'

    if request.method == 'POST':
        form = AuthMethodForm(request.POST, instance=obj, cancel_url=cancel_url)
        if form.is_valid():
            form.save()
            messages.success(request, _('Authentication Method saved successfully.'))
            return redirect(cancel_url)
    else:
        form = AuthMethodForm(instance=obj, cancel_url=cancel_url)

    form_description = {
        'size': '',
        'content': _('''
        <h5>Authentication Types</h5>
        <p>Select how users will authenticate through this method.</p>
        <ul>
            <li><strong>Local Password</strong>: Users will authenticate using a standard username and password stored locally. Only one of this type can be created.</li>
            <li><strong>TOTP (Time-Based One-Time Password)</strong>: Users will need to enter a rotating token from an authenticator app. Requires setting a Global TOTP Secret.</li>
            <li><strong>OIDC (OpenID Connect)</strong>: Users will authenticate via an external identity provider (like Keycloak, Google, or Authelia). Requires Provider URL, Client ID, and Client Secret.</li>
        </ul>
        ''')
    }

    context = {
        'form': form,
        'title': title,
        'page_title': title,
        'form_description': form_description,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_auth_method(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    obj_uuid = request.GET.get('uuid')
    obj = get_object_or_404(AuthMethod, uuid=obj_uuid)
    
    cancel_url = reverse('gatekeeper_list') + '?tab=auth_methods'

    if request.method == 'POST':
        obj.delete()
        messages.success(request, _('Authentication Method deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'object': obj,
        'title': _('Delete Authentication Method'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the authentication method "%(name)s"?') % {'name': obj.name}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_auth_domain(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    obj_uuid = request.GET.get('uuid')
    
    if obj_uuid:
        obj = get_object_or_404(AuthMethodAllowedDomain, uuid=obj_uuid)
        title = _('Edit Allowed Domain')
    else:
        obj = None
        title = _('Add Allowed Domain')

    cancel_url = reverse('gatekeeper_list') + '?tab=allowed_identities'

    if request.method == 'POST':
        form = AuthMethodAllowedDomainForm(request.POST, instance=obj, cancel_url=cancel_url)
        if form.is_valid():
            form.save()
            messages.success(request, _('Allowed Domain saved successfully.'))
            return redirect(cancel_url)
    else:
        form = AuthMethodAllowedDomainForm(instance=obj, cancel_url=cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_auth_domain(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    obj_uuid = request.GET.get('uuid')
    obj = get_object_or_404(AuthMethodAllowedDomain, uuid=obj_uuid)
    
    cancel_url = reverse('gatekeeper_list') + '?tab=allowed_identities'

    if request.method == 'POST':
        obj.delete()
        messages.success(request, _('Allowed Domain deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'object': obj,
        'title': _('Delete Allowed Domain'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the allowed domain "%(domain)s"?') % {'domain': obj.domain}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_auth_email(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    obj_uuid = request.GET.get('uuid')
    
    if obj_uuid:
        obj = get_object_or_404(AuthMethodAllowedEmail, uuid=obj_uuid)
        title = _('Edit Allowed Email')
    else:
        obj = None
        title = _('Add Allowed Email')

    cancel_url = reverse('gatekeeper_list') + '?tab=allowed_identities'

    if request.method == 'POST':
        form = AuthMethodAllowedEmailForm(request.POST, instance=obj, cancel_url=cancel_url)
        if form.is_valid():
            form.save()
            messages.success(request, _('Allowed Email saved successfully.'))
            return redirect(cancel_url)
    else:
        form = AuthMethodAllowedEmailForm(instance=obj, cancel_url=cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_auth_email(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    obj_uuid = request.GET.get('uuid')
    obj = get_object_or_404(AuthMethodAllowedEmail, uuid=obj_uuid)
    
    cancel_url = reverse('gatekeeper_list') + '?tab=allowed_identities'

    if request.method == 'POST':
        obj.delete()
        messages.success(request, _('Allowed Email deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'object': obj,
        'title': _('Delete Allowed Email'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the allowed email "%(email)s"?') % {'email': obj.email}
    }
    return render(request, 'generic_delete_confirmation.html', context)
