import subprocess

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render
from django.utils.translation import gettext_lazy as _

from api.models import WireguardStatusCache
from cluster.models import WorkerStatus
from user_manager.models import UserAcl
from wgwadmlibrary.tools import is_valid_ip_or_hostname
from wireguard.models import WireGuardInstance


@login_required
def view_console(request):
    user_acl = get_object_or_404(UserAcl, user=request.user)

    if not user_acl.enable_console:
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})

    wireguard_instances = WireGuardInstance.objects.all().order_by('instance_id')
    requested_command = request.GET.get('command')
    command_target = request.GET.get('target', '')
    if command_target:
        if not is_valid_ip_or_hostname(command_target):
            command_target = ''
    page_title = _('Console') + ': '
    if requested_command == 'iptables':
        page_title += _('iptables list')
        bash_command = ['bash', '-c', 'iptables -L -nv ; iptables -t nat -L -nv']
    elif requested_command == 'ifconfig':
        page_title += 'ifconfig'
        bash_command = ['bash', '-c', 'ifconfig']
    elif requested_command == 'ps':
        page_title += _('running processes')
        bash_command = ['bash', '-c', 'ps faux']
    elif requested_command == 'wgshow':
        page_title += _('WireGuard show')
        if user_acl.enable_enhanced_filter:
            command_output = _('Enhanced filter is enabled. This command is not available.')
            bash_command = None
            command_success = False
        else:
            bash_command = ['bash', '-c', 'wg show']
    elif requested_command == 'freem':
        page_title += _('Memory usage')
        bash_command = ['bash', '-c', 'free -m']
    elif requested_command == 'route':
        page_title += _('Routing table')
        bash_command = ['bash', '-c', 'route -n']
    elif requested_command == 'top':
        page_title += 'top'
        bash_command = ['bash', '-c', 'top -b -n 1']
    elif requested_command == 'ping':
        page_title = 'ping ' + command_target
        bash_command = ['bash', '-c', 'ping -c 4 ' + command_target]
    elif requested_command == 'traceroute':
        page_title += 'traceroute ' + command_target
        bash_command = ['bash', '-c', 'traceroute ' + command_target]
    elif requested_command == 'testdns':
        page_title += _('DNS container test script')
        bash_command = ['/app/dns/scripts/test_dns_service.sh']
    elif requested_command == 'flush_cache':
        page_title += _('Flush Wireguard status cache')
        bash_command = ''
    else:
        page_title = _('Console') + ': ' + _('Invalid command')
        bash_command = None
        command_output = ''
        command_success = False

    if requested_command == 'flush_cache':
        command_output = ''
        for worker_status in WorkerStatus.objects.all():
            worker_status.wireguard_status = ''
            worker_status.wireguard_status_updated = None
            worker_status.save()
            command_output += _('Flushed WireGuard status cache for worker: ') + str(worker_status.worker) + '\n'
        command_success = True

        wireguard_status_cache_count = WireGuardInstance.objects.all().count()
        WireguardStatusCache.objects.all().delete()
        command_output += _('Flushed WireGuard status cache entries: ') + str(wireguard_status_cache_count) + '\n'
        command_success = True

    if requested_command in ['ping', 'traceroute'] and not command_target:
        command_output = requested_command + ': ' + _('Invalid target')
        bash_command = None
        command_success = False

    if bash_command:
        try:
            command_output = subprocess.check_output(bash_command, stderr=subprocess.STDOUT).decode('utf-8')
            command_success = True
        except subprocess.CalledProcessError as e:
            command_output = e.output.decode('utf-8')
            command_success = False
        
    context = {'page_title': page_title, 'command_output': command_output, 'command_success': command_success}
    return render(request, 'console/console.html', context)