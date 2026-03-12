import io

import pyotp
import qrcode
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.utils.translation import gettext as _

from gatekeeper.forms import GatekeeperUserForm, GatekeeperGroupForm, AuthMethodForm, AuthMethodAllowedDomainForm, \
    AuthMethodAllowedEmailForm, GatekeeperIPAddressForm
from gatekeeper.models import GatekeeperUser, GatekeeperGroup, AuthMethod, AuthMethodAllowedDomain, \
    AuthMethodAllowedEmail, GatekeeperIPAddress
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
    auth_ips = GatekeeperIPAddress.objects.all().order_by('address')
    
    tab = request.GET.get('tab', 'users')
    
    context = {
        'users': users,
        'groups': groups,
        'auth_methods': auth_methods,
        'auth_domains': auth_domains,
        'auth_emails': auth_emails,
        'auth_ips': auth_ips,
        'active_tab': tab,
    }
    return render(request, 'gatekeeper/gatekeeper_list.html', context)


@login_required
def view_manage_gatekeeper_user(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    gatekeeper_user_uuid = request.GET.get('uuid')
    
    if gatekeeper_user_uuid:
        gatekeeper_user = get_object_or_404(GatekeeperUser, uuid=gatekeeper_user_uuid)
        title = _('Edit Gatekeeper User')
    else:
        gatekeeper_user = None
        title = _('Create Gatekeeper User')

    cancel_url = reverse('gatekeeper_list') + '?tab=users'

    form = GatekeeperUserForm(request.POST or None, instance=gatekeeper_user, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('Gatekeeper User saved successfully.'))
        return redirect(cancel_url)

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

    gatekeeper_user = get_object_or_404(GatekeeperUser, uuid=request.GET.get('uuid'))
    
    cancel_url = reverse('gatekeeper_list') + '?tab=users'

    if request.method == 'POST':
        gatekeeper_user.delete()
        messages.success(request, _('Gatekeeper User deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'gatekeeper_user': gatekeeper_user,
        'title': _('Delete Gatekeeper User'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the user "%(username)s"?') % {'username': gatekeeper_user.username}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_gatekeeper_group(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    gatekeeper_group_uuid = request.GET.get('uuid')
    
    if gatekeeper_group_uuid:
        gatekeeper_group = get_object_or_404(GatekeeperGroup, uuid=gatekeeper_group_uuid)
        title = _('Edit Gatekeeper Group')
    else:
        gatekeeper_group = None
        title = _('Create Gatekeeper Group')

    cancel_url = reverse('gatekeeper_list') + '?tab=groups'

    form = GatekeeperGroupForm(request.POST or None, instance=gatekeeper_group, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('Gatekeeper Group saved successfully.'))
        return redirect(cancel_url)

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

    gatekeeper_group = get_object_or_404(GatekeeperGroup, uuid=request.GET.get('uuid'))
    
    cancel_url = reverse('gatekeeper_list') + '?tab=groups'

    if request.method == 'POST':
        gatekeeper_group.delete()
        messages.success(request, _('Gatekeeper Group deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'gatekeeper_group': gatekeeper_group,
        'title': _('Delete Gatekeeper Group'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the group "%(name)s"?') % {'name': gatekeeper_group.name}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_auth_method(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    auth_method_uuid = request.GET.get('uuid')
    
    if auth_method_uuid:
        auth_method = get_object_or_404(AuthMethod, uuid=auth_method_uuid)
        title = _('Edit Authentication Method')
    else:
        auth_method = None
        title = _('Create Authentication Method')

    cancel_url = reverse('gatekeeper_list') + '?tab=auth_methods'

    form = AuthMethodForm(request.POST or None, instance=auth_method, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('Authentication Method saved successfully.'))
        return redirect(cancel_url)

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
    return render(request, 'gatekeeper/gatekeeper_auth_method_form.html', context)


@login_required
def view_delete_auth_method(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    auth_method = get_object_or_404(AuthMethod, uuid=request.GET.get('uuid'))
    
    cancel_url = reverse('gatekeeper_list') + '?tab=auth_methods'

    if request.method == 'POST':
        auth_method.delete()
        messages.success(request, _('Authentication Method deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'auth_method': auth_method,
        'title': _('Delete Authentication Method'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the authentication method "%(name)s"?') % {'name': auth_method.name}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_generate_totp_qr(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return HttpResponse("Access Denied", status=403)

    totp_secret = request.GET.get('secret')
    issuer = request.GET.get('issuer', 'wireguard_webadmin')
    name = request.GET.get('name', 'Gatekeeper')

    if not totp_secret:
        return HttpResponse("No secret provided", status=400)

    try:
        totp = pyotp.TOTP(totp_secret)
        uri = totp.provisioning_uri(name=name, issuer_name=issuer)

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        response = HttpResponse(content_type="image/png")
        img_io = io.BytesIO()
        img.save(img_io, format='PNG')
        img_io.seek(0)
        response.write(img_io.getvalue())
        return response
    except Exception:
        return HttpResponse("Error generating QR code", status=500)


@login_required
def view_manage_auth_domain(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    auth_domain_uuid = request.GET.get('uuid')
    
    if auth_domain_uuid:
        auth_domain = get_object_or_404(AuthMethodAllowedDomain, uuid=auth_domain_uuid)
        title = _('Edit Allowed Domain')
    else:
        auth_domain = None
        title = _('Add Allowed Domain')

    cancel_url = reverse('gatekeeper_list') + '?tab=allowed_identities'

    form = AuthMethodAllowedDomainForm(request.POST or None, instance=auth_domain, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('Allowed Domain saved successfully.'))
        return redirect(cancel_url)

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

    auth_domain = get_object_or_404(AuthMethodAllowedDomain, uuid=request.GET.get('uuid'))
    
    cancel_url = reverse('gatekeeper_list') + '?tab=allowed_identities'

    if request.method == 'POST':
        auth_domain.delete()
        messages.success(request, _('Allowed Domain deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'auth_domain': auth_domain,
        'title': _('Delete Allowed Domain'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the allowed domain "%(domain)s"?') % {'domain': auth_domain.domain}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_auth_email(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    auth_email_uuid = request.GET.get('uuid')
    
    if auth_email_uuid:
        auth_email = get_object_or_404(AuthMethodAllowedEmail, uuid=auth_email_uuid)
        title = _('Edit Allowed Email')
    else:
        auth_email = None
        title = _('Add Allowed Email')

    cancel_url = reverse('gatekeeper_list') + '?tab=allowed_identities'

    form = AuthMethodAllowedEmailForm(request.POST or None, instance=auth_email, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('Allowed Email saved successfully.'))
        return redirect(cancel_url)

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

    auth_email = get_object_or_404(AuthMethodAllowedEmail, uuid=request.GET.get('uuid'))
    
    cancel_url = reverse('gatekeeper_list') + '?tab=allowed_identities'

    if request.method == 'POST':
        auth_email.delete()
        messages.success(request, _('Allowed Email deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'auth_email': auth_email,
        'title': _('Delete Allowed Email'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the allowed email "%(email)s"?') % {'email': auth_email.email}
    }
    return render(request, 'generic_delete_confirmation.html', context)


@login_required
def view_manage_gatekeeper_ip(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    gatekeeper_ip_uuid = request.GET.get('uuid')
    
    if gatekeeper_ip_uuid:
        gatekeeper_ip = get_object_or_404(GatekeeperIPAddress, uuid=gatekeeper_ip_uuid)
        title = _('Edit IP Address')
    else:
        gatekeeper_ip = None
        title = _('Add IP Address')

    cancel_url = reverse('gatekeeper_list') + '?tab=ip_addresses'

    form = GatekeeperIPAddressForm(request.POST or None, instance=gatekeeper_ip, cancel_url=cancel_url)
    if form.is_valid():
        form.save()
        messages.success(request, _('IP Address saved successfully.'))
        return redirect(cancel_url)

    context = {
        'form': form,
        'title': title,
        'page_title': title,
    }
    return render(request, 'generic_form.html', context)


@login_required
def view_delete_gatekeeper_ip(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': _('Access Denied')})

    gatekeeper_ip = get_object_or_404(GatekeeperIPAddress, uuid=request.GET.get('uuid'))
    
    cancel_url = reverse('gatekeeper_list') + '?tab=ip_addresses'

    if request.method == 'POST':
        gatekeeper_ip.delete()
        messages.success(request, _('IP Address deleted successfully.'))
        return redirect(cancel_url)

    context = {
        'gatekeeper_ip': gatekeeper_ip,
        'title': _('Delete IP Address'),
        'cancel_url': cancel_url,
        'text': _('Are you sure you want to delete the IP address "%(address)s"?') % {'address': gatekeeper_ip.address}
    }
    return render(request, 'generic_delete_confirmation.html', context)
