import ipaddress
import subprocess

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _

from user_manager.models import UserAcl
from wgwadmlibrary.tools import check_sort_order_conflict, deduplicate_sort_order, default_sort_peers, \
    user_allowed_instances, user_allowed_peers, user_has_access_to_instance, user_has_access_to_peer
from wireguard.models import Peer, PeerAllowedIP, WireGuardInstance
from wireguard_peer.forms import PeerAllowedIPForm, PeerForm


def generate_peer_default(wireguard_instance):
    private_key = subprocess.check_output('wg genkey', shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f'echo {private_key} | wg pubkey', shell=True).decode('utf-8').strip()
    pre_shared_key = subprocess.check_output('wg genpsk', shell=True).decode('utf-8').strip()

    address = wireguard_instance.address
    netmask = wireguard_instance.netmask
    cidr_network = f"{address}/{netmask}"
    network = ipaddress.ip_network(cidr_network, strict=False)
    
    # the code below can be an issue for larger networks, for now it's fine, but it should be optimized in the future
    used_ips = set(WireGuardInstance.objects.all().values_list('address', flat=True)) | \
               set(PeerAllowedIP.objects.filter(config_file='server', priority=0).values_list('allowed_ip', flat=True))
    
    free_ip_address = None
    for ip in network.hosts():
        if str(ip) not in used_ips:
            free_ip_address = str(ip)
            break
    
    return {
        'name': '',
        'public_key': public_key,
        'pre_shared_key': pre_shared_key,
        'persistent_keepalive': 25,
        'private_key': private_key,
        'wireguard_instance': wireguard_instance,
        'allowed_ip': free_ip_address,
    }


@login_required
def view_wireguard_peer_list(request):
    page_title = _('WireGuard Peer List')
    user_acl = get_object_or_404(UserAcl, user=request.user)
    wireguard_instances = user_allowed_instances(user_acl)

    if wireguard_instances:
        if request.GET.get('uuid'):
            current_instance = get_object_or_404(WireGuardInstance, uuid=request.GET.get('uuid'))
        else:
            current_instance = wireguard_instances.first()
        if current_instance not in wireguard_instances:
            raise Http404
        default_sort_peers(current_instance)
        peer_list = user_allowed_peers(user_acl, current_instance)
    else:
        current_instance = None
        peer_list = None

    add_peer_enabled = False
    if current_instance:
        if user_has_access_to_instance(user_acl, current_instance):
            add_peer_enabled = True
        
    context = {'page_title': page_title, 'wireguard_instances': wireguard_instances, 'current_instance': current_instance, 'peer_list': peer_list, 'add_peer_enabled': add_peer_enabled, 'user_acl': user_acl}
    return render(request, 'wireguard/wireguard_peer_list.html', context)


@login_required
def view_wireguard_peer_sort(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=30).exists():
            return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    peer = get_object_or_404(Peer, uuid=request.GET.get('peer'))
    # check if the current sort order is duplicated with another peer
    if check_sort_order_conflict(peer):
        deduplicate_sort_order(peer.wireguard_instance)
    redirect_url = f'/peer/list/?uuid={peer.wireguard_instance.uuid}#peer-{peer.public_key}'
    direction = request.GET.get('direction')
    sort_order_changed = False
    if direction == 'up':
        previous_peer = Peer.objects.filter(wireguard_instance=peer.wireguard_instance, sort_order__lt=peer.sort_order).order_by('-sort_order').first()                
        if previous_peer:
            peer.sort_order, previous_peer.sort_order = previous_peer.sort_order, peer.sort_order
            peer.save()
            previous_peer.save()
            sort_order_changed = True
        else:
            messages.warning(request, 'Cannot move peer up|Peer is already at the top.')
    elif direction == 'down':
        next_peer = Peer.objects.filter(wireguard_instance=peer.wireguard_instance, sort_order__gt=peer.sort_order).order_by('sort_order').first()
        if next_peer:
            peer.sort_order, next_peer.sort_order = next_peer.sort_order, peer.sort_order
            peer.save()
            next_peer.save()
            sort_order_changed = True
        else:
            messages.warning(request, 'Cannot move peer down|Peer is already at the bottom.')

    if sort_order_changed:
        # check if the new sort order is duplicated with another peer
        if check_sort_order_conflict(peer):
            deduplicate_sort_order(peer.wireguard_instance)

    return redirect(redirect_url)


@login_required
def view_wireguard_peer_manage(request):
    if request.method == 'POST':
        if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=30).exists():
            return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    else:
        if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=20).exists():
            return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    user_acl = get_object_or_404(UserAcl, user=request.user)

    if request.GET.get('instance'):
        current_instance = get_object_or_404(WireGuardInstance, uuid=request.GET.get('instance'))
        if not user_has_access_to_instance(user_acl, current_instance):
            raise Http404
        current_peer = None
        page_title = 'Create a new Peer for instance wg' + str(current_instance.instance_id)
        new_peer_data = generate_peer_default(current_instance)

        if new_peer_data['allowed_ip']:
            new_peer = Peer.objects.create(
                name=new_peer_data['name'],
                public_key=new_peer_data['public_key'],
                pre_shared_key=new_peer_data['pre_shared_key'],
                persistent_keepalive=new_peer_data['persistent_keepalive'],
                private_key=new_peer_data['private_key'],
                wireguard_instance=current_instance,
            )
            PeerAllowedIP.objects.create(
                config_file='server',
                peer=new_peer,
                allowed_ip=new_peer_data['allowed_ip'],
                priority=0,
                netmask=32,
            )
            messages.success(request, 'Peer created|Peer for instance wg' + str(current_instance.instance_id) + ' created successfully with IP ' + new_peer_data['allowed_ip'] + '/32.')
            new_peer.wireguard_instance.pending_changes = True
            new_peer.wireguard_instance.save()
            return redirect('/peer/manage/?peer=' + str(new_peer.uuid))
        else:
            messages.warning(request, 'Error creating peer|No available IP address found for peer creation.')
            return redirect('/peer/list/')
            
    elif request.GET.get('peer'):
        current_peer = get_object_or_404(Peer, uuid=request.GET.get('peer'))
        if not user_has_access_to_peer(user_acl, current_peer):
            raise Http404
        current_instance = current_peer.wireguard_instance
        if request.GET.get('action') == 'delete':
            if request.GET.get('confirmation') == 'delete':
                current_peer.wireguard_instance.pending_changes = True
                current_peer.wireguard_instance.save()
                current_peer.delete()
                messages.success(request, 'Peer deleted|Peer deleted successfully.')
                return redirect('/peer/list/?uuid=' + str(current_instance.uuid))
            else:
                messages.warning(request, 'Error deleting peer|Invalid confirmation message. Type "delete" to confirm.')
                return redirect('/peer/manage/?peer=' + str(current_peer.uuid))
        page_title = 'Update Peer '
        peer_ip_list = current_peer.peerallowedip_set.filter(config_file='server').order_by('priority')
        peer_client_ip_list = current_peer.peerallowedip_set.filter(config_file='client').order_by('priority')
        if current_peer.name:
            page_title += current_peer.name
        else:
            page_title += current_peer.public_key[:16] + ("..." if len(current_peer.public_key) > 16 else "")
        if request.method == 'POST':
            form = PeerForm(request.POST, instance=current_peer)
            if form.is_valid():
                form.save()
                messages.success(request, 'Peer updated|Peer updated successfully.')
                current_peer.wireguard_instance.pending_changes = True
                current_peer.wireguard_instance.save()
                return redirect('/peer/list/?uuid=' + str(current_peer.wireguard_instance.uuid))
        else:
            form = PeerForm(instance=current_peer)
    else:
        return redirect('/peer/list/')
    context = {
        'page_title': page_title, 'current_instance': current_instance, 'current_peer': current_peer, 'form': form,
        'peer_ip_list': peer_ip_list, 'peer_client_ip_list': peer_client_ip_list
        }
    return render(request, 'wireguard/wireguard_manage_peer.html', context)


def view_manage_ip_address(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=30).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})

    user_acl = get_object_or_404(UserAcl, user=request.user)
    config_file = request.GET.get('config', 'server')

    if request.GET.get('peer'):
        current_peer = get_object_or_404(Peer, uuid=request.GET.get('peer'))
        current_ip = None
        if not user_has_access_to_peer(user_acl, current_peer):
            raise Http404
        
    elif request.GET.get('ip'):
        current_ip = get_object_or_404(PeerAllowedIP, uuid=request.GET.get('ip'))
        current_peer = current_ip.peer
        config_file = current_ip.config_file
        if not user_has_access_to_peer(user_acl, current_peer):
            raise Http404

        if request.GET.get('action') == 'delete':
            if request.GET.get('confirmation') == 'delete':
                current_ip.delete()
                messages.success(request, 'IP address deleted|IP address deleted successfully.')
                current_peer.wireguard_instance.pending_changes = True
                current_peer.wireguard_instance.save()
                return redirect('/peer/manage/?peer=' + str(current_peer.uuid))
            else:
                messages.warning(request, 'Error deleting IP address|Invalid confirmation message. Type "delete" to confirm.')
                return redirect('/peer/ip/?ip=' + str(current_ip.uuid))
    if config_file not in ['client', 'server']:
        config_file = 'server'
    if config_file == 'client':
        page_title = 'Manage client route'
    else:
        page_title = 'Manage IP address or Network'

    if request.method == 'POST':
        form = PeerAllowedIPForm(request.POST or None, instance=current_ip, current_peer=current_peer, config_file=config_file)
        if form.is_valid():
            this_form = form.save(commit=False)
            if not current_ip:
                this_form.peer = current_peer
            this_form.config_file = config_file
            this_form.save()
            current_peer.wireguard_instance.pending_changes = True
            current_peer.wireguard_instance.save()
            if current_ip:
                messages.success(request, 'IP address updated|IP address updated successfully.')
            else:
                messages.success(request, 'IP address added|IP address added successfully.')
            return redirect('/peer/manage/?peer=' + str(current_peer.uuid))
    else:
        form = PeerAllowedIPForm(instance=current_ip, current_peer=current_peer)

    
    return render(request, 'wireguard/wireguard_manage_ip.html', {
        'page_title': page_title, 'form': form, 'current_peer': current_peer, 'current_ip': current_ip
        })  
