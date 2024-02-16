from wireguard.models import WireGuardInstance
from wgwadmlibrary.tools import is_valid_ip_or_hostname
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
import subprocess


@login_required
def view_console(request):
    page_title = 'Console'
    wireguard_instances = WireGuardInstance.objects.all().order_by('instance_id')
    if wireguard_instances.filter(pending_changes=True).exists():
        pending_changes_warning = True
    else:
        pending_changes_warning = False
    requested_command = request.GET.get('command')
    command_target = request.GET.get('target', '')
    if command_target:
        if not is_valid_ip_or_hostname(command_target):
            command_target = ''

    if requested_command == 'iptables':
        page_title = 'Console: iptables list'
        bash_command = ['bash', '-c', 'iptables -L -nv ; iptables -t nat -L -nv']
    elif requested_command == 'ifconfig':
        page_title = 'Console: ifconfig'
        bash_command = ['bash', '-c', 'ifconfig']
    elif requested_command == 'ps':
        page_title = 'Console: running processes'
        bash_command = ['bash', '-c', 'ps faux']
    elif requested_command == 'wgshow':
        page_title = 'Console: WireGuard show'
        bash_command = ['bash', '-c', 'wg show']
    elif requested_command == 'freem':
        page_title = 'Console: Memory usage'
        bash_command = ['bash', '-c', 'free -m']
    elif requested_command == 'route':
        page_title = 'Console: top'
        bash_command = ['bash', '-c', 'route -n']
    elif requested_command == 'top':
        page_title = 'Console: top'
        bash_command = ['bash', '-c', 'top -b -n 1']
    elif requested_command == 'ping':
        page_title = 'Console: ping ' + command_target
        bash_command = ['bash', '-c', 'ping -c 4 ' + command_target]
    elif requested_command == 'traceroute':
        page_title = 'Console: traceroute ' + command_target
        bash_command = ['bash', '-c', 'traceroute ' + command_target]
    else:
        bash_command = None
        command_output = ''
        command_success = False
    
    if requested_command == 'ping' or requested_command == 'traceroute':
        if not command_target:
            command_output = requested_command + ': Invalid target'
            bash_command = None
            command_success = False

    if bash_command:
        try:
            command_output = subprocess.check_output(bash_command, stderr=subprocess.STDOUT).decode('utf-8')
            command_success = True
        except subprocess.CalledProcessError as e:
            command_output = e.output.decode('utf-8')
            command_success = False
        
    context = {'page_title': page_title, 'command_output': command_output, 'command_success': command_success, 'pending_changes_warning': pending_changes_warning}  
    return render(request, 'console/console.html', context)