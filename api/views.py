from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.utils import timezone
from wireguard.models import WebadminSettings
import requests
import subprocess


@login_required
@require_http_methods(["GET"])
def wireguard_status(request):
    commands = {
        'latest-handshakes': "wg show all latest-handshakes | expand | tr -s ' '",
        'allowed-ips': "wg show all allowed-ips | expand | tr -s ' '",
        'transfer': "wg show all transfer | expand | tr -s ' '",
        'endpoints': "wg show all endpoints | expand | tr -s ' '",
    }

    output = {}

    for key, command in commands.items():
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            return JsonResponse({'error': stderr}, status=400)

        current_interface = None
        for line in stdout.strip().split('\n'):
            parts = line.split()  
            if len(parts) >= 3:
                interface, peer, value = parts[0], parts[1], " ".join(parts[2:])
                current_interface = interface
            else:
                continue

            if interface not in output:
                output[interface] = {}

            if peer not in output[interface]:
                output[interface][peer] = {
                    'allowed-ips': [],
                    'latest-handshakes': '',
                    'transfer': {'tx': 0, 'rx': 0},
                    'endpoints': '',
                }

            if key == 'allowed-ips':
                output[interface][peer]['allowed-ips'].append(value)
            elif key == 'transfer':
                tx, rx = value.split()[-2:]  
                output[interface][peer]['transfer'] = {'tx': int(tx), 'rx': int(rx)}
            elif key == 'endpoints':
                output[interface][peer]['endpoints'] = value
            else:
                output[interface][peer][key] = value

    return JsonResponse(output)


def cron_check_updates(request):
    webadmin_settings, webadmin_settings_created = WebadminSettings.objects.get_or_create(name='webadmin_settings')

    if webadmin_settings.last_checked is None or timezone.now() - webadmin_settings.last_checked > timezone.timedelta(hours=6):
        try:
            version = settings.WIREGUARD_WEBADMIN_VERSION / 10000
            url = f'https://updates.eth0.com.br/api/check_updates/?app=wireguard_webadmin&version={version}'
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            
            if 'update_available' in data:
                webadmin_settings.update_available = data['update_available']
                
                if data['update_available']:
                    webadmin_settings.latest_version = float(data['current_version']) * 10000
                    
                webadmin_settings.last_checked = timezone.now()
                webadmin_settings.save()

                response_data = {
                    'update_available': webadmin_settings.update_available,
                    'latest_version': webadmin_settings.latest_version,
                    'current_version': settings.WIREGUARD_WEBADMIN_VERSION,
                }
                return JsonResponse(response_data)
            
        except Exception as e:
            webadmin_settings.update_available = False
            webadmin_settings.save()
            return JsonResponse({'update_available': False})
    
    return JsonResponse({'update_available': webadmin_settings.update_available})
