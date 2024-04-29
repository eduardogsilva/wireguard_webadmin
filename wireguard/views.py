from decimal import Decimal, ROUND_DOWN
from django.shortcuts import render, get_object_or_404, redirect
from user_manager.models import UserAcl

from wireguard.forms import WireGuardInstanceForm
from .models import WireGuardInstance, WebadminSettings
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import models
from django.conf import settings
import os
import subprocess


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
def view_welcome(request):
    #page_title = 'Welcome'
    #context = {'page_title': page_title}
    return render(request, 'wireguard/welcome.html')


@login_required
def view_wireguard_status(request):
    page_title = 'WireGuard Status'
    wireguard_instances = WireGuardInstance.objects.all().order_by('instance_id')
    if wireguard_instances.filter(pending_changes=True).exists():
        pending_changes_warning = True
    else:
        pending_changes_warning = False
    bash_command = ['bash', '-c', 'wg show']
    try:
        command_output = subprocess.check_output(bash_command, stderr=subprocess.STDOUT).decode('utf-8')
        command_success = True
    except subprocess.CalledProcessError as e:
        command_output = e.output.decode('utf-8')
        command_success = False
    
    context = {'page_title': page_title, 'command_output': command_output, 'command_success': command_success, 'pending_changes_warning': pending_changes_warning, 'wireguard_instances': wireguard_instances}
    return render(request, 'wireguard/wireguard_status.html', context)


@login_required
def view_wireguard_manage_instance(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=50).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    wireguard_instances = WireGuardInstance.objects.all().order_by('instance_id')
    if wireguard_instances.filter(pending_changes=True).exists():
        pending_changes_warning = True
    else:
        pending_changes_warning = False
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
    context = {'page_title': page_title, 'wireguard_instances': wireguard_instances, 'current_instance': current_instance, 'form': form, 'pending_changes_warning': pending_changes_warning}
    return render(request, 'wireguard/wireguard_manage_server.html', context)