from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseForbidden

from django.conf import settings
from django.utils import timezone
from wireguard.models import WebadminSettings, Peer, PeerStatus
import requests
import subprocess
import datetime
import pytz
import os
import uuid


def get_api_key():
    api_file_path = '/etc/wireguard/api_key'
    api_key = None

    if os.path.exists(api_file_path) and os.path.isfile(api_file_path):
        with open(api_file_path, 'r') as api_file:
            api_file_content = api_file.read().strip()
            try:
                uuid_test = uuid.UUID(api_file_content)

                if str(uuid_test) == api_file_content:
                    api_key = str(uuid_test)
            except:
                pass

    return api_key


@require_http_methods(["GET"])
def wireguard_status(request):
    if request.user.is_authenticated:
        pass
    elif request.GET.get('key'):
        api_key = get_api_key()
        if api_key and api_key == request.GET.get('key'):
            pass
        else:
            return HttpResponseForbidden()
    else:
        return HttpResponseForbidden()

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
            elif len(parts) == 2 and current_interface:
                peer, value = parts
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


@require_http_methods(["GET"])
def cron_update_peer_latest_handshake(request):
    command = "wg show all latest-handshakes | expand | tr -s ' '"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        return JsonResponse({'error': stderr}, status=400)
    #debug_information = []
    for line in stdout.strip().split('\n'):
        parts = line.split()
        if len(parts) < 3:
            continue
        interface, peer_public_key, latest_handshake = parts[0], parts[1], parts[2]
        latest_handshake_timestamp = int(latest_handshake)

        if latest_handshake_timestamp > 0:
            last_handshake_time = datetime.datetime.fromtimestamp(latest_handshake_timestamp, tz=pytz.utc)
            #debug_information.append(f'Last handshake for {peer_public_key} is {last_handshake_time}')
            peer = Peer.objects.filter(public_key=peer_public_key).first()
            if peer:
                #debug_information.append(f'Peer found: {peer.public_key}')
                peer_status, created = PeerStatus.objects.get_or_create(
                    peer=peer,
                    defaults={'last_handshake': last_handshake_time}
                )
                if not created:
                    if peer_status.last_handshake != last_handshake_time:
                        #debug_information.append(f'Updating last_handshake for {peer.public_key} to {last_handshake_time}')
                        peer_status.last_handshake = last_handshake_time
                        peer_status.save()
                    #else:
                    #    debug_information.append(f'No changes for {peer.public_key}')

    return JsonResponse({'status': 'success'})


def cron_check_updates(request):
    webadmin_settings, webadmin_settings_created = WebadminSettings.objects.get_or_create(name='webadmin_settings')

    if webadmin_settings.last_checked is None or timezone.now() - webadmin_settings.last_checked > timezone.timedelta(hours=1):
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
