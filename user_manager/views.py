from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.sessions.models import Session
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _

from user_manager.models import UserAcl
from wireguard.models import PeerGroup
from .forms import PeerGroupForm
from .forms import UserAclForm


@login_required
def view_peer_group_list(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    page_title = _('Peer Groups')
    peer_group_list = PeerGroup.objects.all().order_by('name')
    context = {'page_title': page_title, 'peer_group_list': peer_group_list}
    return render(request, 'user_manager/peer_group_list.html', context)


@login_required
def view_peer_group_manage(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    peer_group = None
    if 'uuid' in request.GET:
        peer_group = get_object_or_404(PeerGroup, uuid=request.GET['uuid'])
        form = PeerGroupForm(instance=peer_group, user_id=request.user.id)
        page_title = _('Edit Peer Group: ') + peer_group.name
        if request.GET.get('action') == 'delete':
            group_name = peer_group.name
            if request.GET.get('confirmation') == 'delete':
                peer_group.delete()
                messages.success(request, _('Peer Group deleted|Peer Group deleted: ') + group_name)
                return redirect('/user/peer-group/list/')
            else:
                messages.warning(request, _('Peer Group not deleted|Invalid confirmation.'))
            return redirect('/user/peer-group/list/')
    else:
        form = PeerGroupForm(user_id=request.user.id)
        page_title = _('Add Peer Group')

    if request.method == 'POST':
        if peer_group:
            form = PeerGroupForm(request.POST, instance=peer_group, user_id=request.user.id)
        else:
            form = PeerGroupForm(request.POST, user_id=request.user.id)

        if form.is_valid():
            peer_group = form.save()
            form.save_m2m()
            return redirect('/user/peer-group/list/')
        
    form_description = {
        'size': '',
        'content': _('''
        <h5>Peers</h5>
        <p>Select which peers can be managed by users with this peer group.</p>

        <h5>WireGuard Instances</h5>
        <p>All peers in this WireGuard instance can be managed by users with this peer group, including adding or removing peers.</p>
        ''')
    }
    context = {'page_title': page_title, 'form': form, 'peer_group': peer_group, 'instance': peer_group, 'form_description': form_description}
    return render(request, 'generic_form.html', context)


@login_required
def view_user_list(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    page_title = _('User Manager')
    user_acl_list = UserAcl.objects.all().order_by('user__username')
    context = {'page_title': page_title, 'user_acl_list': user_acl_list}
    return render(request, 'user_manager/list.html', context)


@login_required
def view_manage_user(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    
    user_acl = None
    user = None
    initial_data = {}
    
    if 'uuid' in request.GET:
        user_acl = get_object_or_404(UserAcl, uuid=request.GET['uuid'])
        user = user_acl.user
        initial_data = {
            'username': user.username,
            'user_level': user_acl.user_level,
            'peer_groups': user_acl.peer_groups.all()
        }
        form = UserAclForm(initial=initial_data, instance=user, user_id=user.id)
        page_title = _('Edit User') + f' {user.username}'
        
        if request.GET.get('action') == 'delete':
            username = user.username
            if request.GET.get('confirmation') == username:
                user.delete()
                messages.success(request, _('User deleted|User deleted: ') + username)
                return redirect('/user/list/')
            else:
                messages.warning(request, _('User not deleted|Invalid confirmation.'))
            return redirect('/user/list/')
    else:
        form = UserAclForm()
        page_title = _('Add User')

    if request.method == 'POST':
        if user:
            form = UserAclForm(request.POST, instance=user, user_id=user.id)
        else:
            form = UserAclForm(request.POST)

        if form.is_valid():
            saved_user = form.save()
            if form.cleaned_data.get('password1'):
                user_disconnected = False
                if user:
                    for session in Session.objects.all():
                        if str(user.id) == session.get_decoded().get('_auth_user_id'):
                            session.delete()
                            if not user_disconnected:
                                messages.warning(request, _('User Disconnected|User Disconnected: ') + user.username)
                                user_disconnected = True
            
            if user:
                messages.success(request, _('User updated|User updated: ') + form.cleaned_data['username'])
            else:
                messages.success(request, _('User created|User created: ') + form.cleaned_data['username'])
            return redirect('/user/list/')

    form_description = {
        'size': '',
        'content': _('''
        <h4>User Levels</h4>
        <h5>Debugging Analyst</h5>
        <p>Access to basic system information and logs for troubleshooting. No access to modify settings or view sensitive data such as peer keys.</p>

        <h5>View Only</h5>
        <p>Full view access, including peer keys and configuration files. Cannot modify any settings or configurations.</p>

        <h5>Peer Manager</h5>
        <p>Permissions to add, edit, and remove peers and IP addresses. Does not include access to modify WireGuard instance configurations or higher-level settings.</p>

        <h5>Wireguard Manager</h5>
        <p>Authority to add, edit, and remove configurations of WireGuard instances.</p>

        <h5>Administrator</h5>
        <p>Full access across the system. Can view and modify all settings, configurations and manage users. </p>

        <br>
        <h4>Peer Groups</h4>
        <p>Select which peer groups this user can access. If no peer groups are selected, the user will have access to all peers.</p>

        <h4>Console</h4>
        <p>Enable or disable web console access for this user.</p>

        <h4>Enhanced Filter</h4>
        <p>This option filters the API status response to include only peers that the user has access to. Depending on the size of your environment, enabling this option may impact performance. To mitigate this, consider increasing the "Web Refresh Interval" to reduce the number of requests.</p>

        ''')
    }
    
    context = {
        'page_title': page_title, 
        'form': form, 
        'user_acl': user_acl, 
        'instance': user_acl,
        'form_description': form_description,
        'delete_confirmation_message': _('Please type the username to proceed.')
    }
    return render(request, 'generic_form.html', context)