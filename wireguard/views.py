import subprocess

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import models
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _

from user_manager.models import UserAcl
from wireguard.forms import WireGuardInstanceForm
from .models import WebadminSettings, WireGuardInstance


def generate_instance_defaults():
    max_instance_id = WireGuardInstance.objects.all().aggregate(models.Max('instance_id'))['instance_id__max']
    new_instance_id = (max_instance_id + 1) if max_instance_id is not None else 0

    max_listen_port = WireGuardInstance.objects.all().aggregate(models.Max('listen_port'))['listen_port__max']
    new_listen_port = (max_listen_port + 1) if max_listen_port is not None else 51820

    new_private_key = subprocess.check_output('wg genkey', shell=True).decode('utf-8').strip()
    new_public_key = subprocess.check_output(f'echo {new_private_key} | wg pubkey', shell=True).decode('utf-8').strip()

    new_address = f'10.188.{new_instance_id}.1'

    address_parts = new_address.split('.')
    if len(address_parts) == 4:
        network = f"10.{address_parts[1]}.{address_parts[2]}.0/24"
        port = new_listen_port
        instance_id = new_instance_id
        interface_name = f"wg{instance_id}"

        #post_up_script = (
        #    f"iptables -t nat -A POSTROUTING -s {network} -o eth0 -j MASQUERADE\n"
        #    f"iptables -A INPUT -p udp -m udp --dport {port} -j ACCEPT\n"
        #    f"iptables -A FORWARD -i {interface_name} -o eth0 -d 10.0.0.0/8 -j REJECT\n"
        #    f"iptables -A FORWARD -i {interface_name} -o eth0 -d 172.16.0.0/12 -j REJECT\n"
        #    f"iptables -A FORWARD -i {interface_name} -o eth0 -d 192.168.0.0/16 -j REJECT\n"
        #    f"iptables -A FORWARD -i {interface_name} -j ACCEPT\n"
        #    f"iptables -A FORWARD -o {interface_name} -j ACCEPT"
        #)

        #post_down_script = (
        #    f"iptables -t nat -D POSTROUTING -s {network} -o eth0 -j MASQUERADE\n"
        #    f"iptables -D INPUT -p udp -m udp --dport {port} -j ACCEPT\n"
        #    f"iptables -D FORWARD -i {interface_name} -o eth0 -d 10.0.0.0/8 -j REJECT\n"
        #    f"iptables -D FORWARD -i {interface_name} -o eth0 -d 172.16.0.0/12 -j REJECT\n"
        #    f"iptables -D FORWARD -i {interface_name} -o eth0 -d 192.168.0.0/16 -j REJECT\n"
        #    f"iptables -D FORWARD -i {interface_name} -j ACCEPT\n"
        #    f"iptables -D FORWARD -o {interface_name} -j ACCEPT"
        #)
        post_up_script = ''
        post_down_script = ''

    return {
        'name': '',
        'instance_id': new_instance_id,
        'listen_port': new_listen_port,
        'private_key': new_private_key,
        'public_key': new_public_key,
        'address': new_address,
        'dns_primary': new_address,
        'netmask': 24,
        'persistent_keepalive': 25,
        'hostname': 'myserver.example.com',
        'post_up': post_up_script,
        'post_down': post_down_script,
    }


@login_required
def legacy_view_wireguard_status(request):
    user_acl = get_object_or_404(UserAcl, user=request.user)
    page_title = 'WireGuard Status'
    wireguard_instances = WireGuardInstance.objects.all().order_by('instance_id')

    if user_acl.enable_enhanced_filter:
        command_output = 'Enhanced filter is enabled. This command is not available.'
        command_success = True
    else:
        bash_command = ['bash', '-c', 'wg show']
        try:
            command_output = subprocess.check_output(bash_command, stderr=subprocess.STDOUT).decode('utf-8')
            command_success = True
        except subprocess.CalledProcessError as e:
            command_output = e.output.decode('utf-8')
            command_success = False
    
    context = {'page_title': page_title, 'command_output': command_output, 'command_success': command_success, 'wireguard_instances': wireguard_instances}
    return render(request, 'wireguard/wireguard_status.html', context)


@login_required
def view_wireguard_status(request):
    user_acl = get_object_or_404(UserAcl, user=request.user)
    page_title = _("WireGuard Status")

    if user_acl.peer_groups.exists():
        wireguard_instances = []
        for peer_group in user_acl.peer_groups.all():
            for instance_temp in peer_group.server_instance.all():
                if instance_temp not in wireguard_instances:
                        wireguard_instances.append(instance_temp)
    else:
        wireguard_instances = WireGuardInstance.objects.all().order_by('instance_id')

    if user_acl.enable_enhanced_filter:
        pass

    context = {'page_title': page_title, 'wireguard_instances': wireguard_instances}
    return render(request, 'wireguard/wireguard_status.html', context)


@login_required
def view_wireguard_manage_instance(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    wireguard_instances = WireGuardInstance.objects.all().order_by('instance_id')
    if request.GET.get('uuid'):
        current_instance = get_object_or_404(WireGuardInstance, uuid=request.GET.get('uuid'))
    else:
        if request.GET.get('action') == 'create':
            current_instance = None
        else:
            current_instance = wireguard_instances.first()
    if current_instance:
        page_title = f'wg{current_instance.instance_id}'
        message_title = 'Update WireGuard Instance'
        if current_instance.name:
            page_title += f' ({current_instance.name})'
        if request.GET.get('action') == 'delete':
            message_title = 'Delete WireGuard Instance'
            if request.GET.get('confirmation') == 'delete wg' + str(current_instance.instance_id):
                if current_instance.peer_set.all().count() > 0:
                    messages.warning(request, 'Error removing wg' +str(current_instance.instance_id) + '|Cannot delete WireGuard instance wg' + str(current_instance.instance_id) + '. There are still peers associated with this instance.')
                    return redirect('/server/manage/?uuid=' + str(current_instance.uuid))
                current_instance.delete()
                messages.success(request, message_title + '|WireGuard instance wg' + str(current_instance.instance_id) + ' deleted successfully.')
                return redirect('/server/manage/')
            else:
                messages.warning(request, 'Invalid confirmation' + '|Please confirm deletion of WireGuard instance wg' + str(current_instance.instance_id))
            return redirect('/server/manage/?uuid=' + str(current_instance.uuid))

    else:
        page_title = 'Create a new WireGuard Instance'
        message_title = 'New WireGuard Instance'
    
    if request.method == 'POST':
        form = WireGuardInstanceForm(request.POST, instance=current_instance)
        if form.is_valid():
            this_form = form.save(commit=False)
            this_form.pending_changes = True
            this_form.save()
            messages.success(request, message_title + '|WireGuard instance wg' + str(form.instance.instance_id) + ' saved successfully.')
            return redirect('/server/manage/?uuid=' + str(form.instance.uuid))
    else:
        if not current_instance:
            form = WireGuardInstanceForm(initial=generate_instance_defaults())
        else:
            form = WireGuardInstanceForm(instance=current_instance)  
    context = {'page_title': page_title, 'wireguard_instances': wireguard_instances, 'current_instance': current_instance, 'form': form}
    return render(request, 'wireguard/wireguard_manage_server.html', context)


@login_required
def view_apply_db_patches(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return redirect('/status/')
    webadmin_settings, webadmin_settings_created = WebadminSettings.objects.get_or_create(name='webadmin_settings')
    update_applied = False
    update_list = []

    if webadmin_settings.db_patch_version < 1:
        print('Applying DB patch 1')
        object_list = []
        for wg_instance in WireGuardInstance.objects.filter(peer_list_refresh_interval__gt=10):
            object_list.append(f'wg{wg_instance.instance_id}')
            wg_instance.peer_list_refresh_interval = 10
            wg_instance.save()

        if object_list:
            update_applied = True
            update_list.append({
                'patch_version': 1, 'object_list': object_list,
                'field': 'peer_list_refresh_interval', 'new_value': '10',
                'reason': 'The interval has been reduced to improve the user experience on the peer list. This <b>may impact server performance</b> in larger environments. You can modify this interval in "Server Settings."'
            })
        webadmin_settings.db_patch_version = 1
        webadmin_settings.save()

    data = {
        'update_applied': update_applied,
        'update_list': update_list,
    }
    if update_applied:
        return render(request, 'wireguard/welcome.html', context=data)
    else:
        return redirect('/status/')



