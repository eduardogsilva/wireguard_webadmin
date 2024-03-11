import os
import re
import qrcode
import subprocess
from django.http import HttpResponse
from django.shortcuts import redirect, get_object_or_404, render
from firewall.tools import generate_firewall_header, generate_firewall_footer, generate_port_forward_firewall, export_user_firewall
from user_manager.models import UserAcl
from wireguard.models import WireGuardInstance, Peer, PeerAllowedIP
from firewall.models import RedirectRule
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from io import BytesIO


def clean_command_field(command_field):
    cleaned_field = re.sub(r'[\r\n]+', '; ', command_field)
    cleaned_field = re.sub(r'[\x00-\x1F\x7F]+', '', cleaned_field)
    return cleaned_field


def generate_peer_config(peer_uuid):
    peer = get_object_or_404(Peer, uuid=peer_uuid)
    wg_instance = peer.wireguard_instance

    priority_zero_ip = PeerAllowedIP.objects.filter(config_file='server', peer=peer, priority=0).first()

    if not priority_zero_ip:
        return "No IP with priority zero found for this peer."

    client_address = f"{priority_zero_ip.allowed_ip}/{priority_zero_ip.netmask}"

    allowed_ips = PeerAllowedIP.objects.filter(peer=peer, config_file='client').order_by('priority')
    if allowed_ips:
        allowed_ips_line = ", ".join([f"{ip.allowed_ip}/{ip.netmask}" for ip in allowed_ips])
    else:
        allowed_ips_line = "0.0.0.0/0, ::/0"
    dns_entries = [wg_instance.dns_primary, wg_instance.dns_secondary]
    dns_line = ", ".join(filter(None, dns_entries))

    config_lines = [
        "[Interface]",
        f"PrivateKey = {peer.private_key}" if peer.private_key else "",
        f"Address = {client_address}",
        f"DNS = {dns_line}" if dns_line else "",
        "\n[Peer]",
        f"PublicKey = {wg_instance.public_key}",
        f"Endpoint = {wg_instance.hostname}:{wg_instance.listen_port}",
        f"AllowedIPs = {allowed_ips_line}",
        f"PresharedKey = {peer.pre_shared_key}" if peer.pre_shared_key else "",
        f"PersistentKeepalive = {peer.persistent_keepalive}",
    ]
    return "\n".join(config_lines)


def export_firewall_configuration():
    firewall_content = generate_firewall_header()
    firewall_content += generate_port_forward_firewall()
    firewall_content += export_user_firewall()
    firewall_content += generate_firewall_footer()
    firewall_path = "/etc/wireguard/wg-firewall.sh"
    with open(firewall_path, "w") as firewall_file:
        firewall_file.write(firewall_content)
    subprocess.run(['chmod', '+x', firewall_path], check=True)
    return


@login_required
def export_wireguard_configs(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=30).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    instances = WireGuardInstance.objects.all()
    base_dir = "/etc/wireguard"

    export_firewall_configuration()
    
    firewall_inserted = False
    for instance in instances:
        if instance.legacy_firewall:
            post_up_processed = clean_command_field(instance.post_up) if instance.post_up else ""
            post_down_processed = clean_command_field(instance.post_down) if instance.post_down else ""
            
            if post_up_processed:
                post_up_processed += '; '
            if post_down_processed:
                post_down_processed += '; '

            for redirect_rule in RedirectRule.objects.filter(wireguard_instance=instance):
                rule_text_up = ""
                rule_text_down = ""
                rule_destination = redirect_rule.ip_address
                if redirect_rule.peer:
                    peer_allowed_ip_address = PeerAllowedIP.objects.filter(config_file='server', peer=redirect_rule.peer, netmask=32, priority=0).first()
                    if peer_allowed_ip_address:
                        rule_destination = peer_allowed_ip_address.allowed_ip
                if rule_destination:
                    rule_text_up   = f"iptables -t nat -A PREROUTING -p {redirect_rule.protocol} -d wireguard-webadmin --dport {redirect_rule.port} -j DNAT --to-dest {rule_destination}:{redirect_rule.port} ; "
                    rule_text_down = f"iptables -t nat -D PREROUTING -p {redirect_rule.protocol} -d wireguard-webadmin --dport {redirect_rule.port} -j DNAT --to-dest {rule_destination}:{redirect_rule.port} ; "
                    if redirect_rule.add_forward_rule:
                        rule_text_up   += f"iptables -A FORWARD -d {rule_destination} -p {redirect_rule.protocol} --dport {redirect_rule.port} -j ACCEPT ; "
                        rule_text_down += f"iptables -D FORWARD -d {rule_destination} -p {redirect_rule.protocol} --dport {redirect_rule.port} -j ACCEPT ; "
                    if redirect_rule.masquerade_source:
                        rule_text_up   += f"iptables -t nat -A POSTROUTING -d {rule_destination} -p {redirect_rule.protocol} --dport {redirect_rule.port} -j MASQUERADE ; "
                        rule_text_down += f"iptables -t nat -D POSTROUTING -d {rule_destination} -p {redirect_rule.protocol} --dport {redirect_rule.port} -j MASQUERADE ; "
                    post_up_processed += rule_text_up
                    post_down_processed += rule_text_down
                    
            pass
        else:
            post_down_processed = ''
            
            if not firewall_inserted:
                post_up_processed = '/etc/wireguard/wg-firewall.sh'
                firewall_inserted = True
            else:
                post_up_processed = ''
            

        config_lines = [
            "[Interface]",
            f"PrivateKey = {instance.private_key}",
            f"Address = {instance.address}/{instance.netmask}",
            f"ListenPort = {instance.listen_port}",
            f"PostUp = {post_up_processed}",
            f"PostDown = {post_down_processed}",
        ]

        peers = Peer.objects.filter(wireguard_instance=instance)
        for peer in peers:
            peer_lines = [
                "[Peer]",
                f"PublicKey = {peer.public_key}",
                f"PresharedKey = {peer.pre_shared_key}" if peer.pre_shared_key else "",
                f"PersistentKeepalive = {peer.persistent_keepalive}",
            ]
            allowed_ips = PeerAllowedIP.objects.filter(config_file='server', peer=peer).order_by('priority')
            allowed_ips_line = "AllowedIPs = " + ", ".join([f"{ip.allowed_ip}/{ip.netmask}" for ip in allowed_ips])
            peer_lines.append(allowed_ips_line)
            config_lines.extend(peer_lines)
            config_lines.append("")

        config_content = "\n".join(config_lines)
        config_path = os.path.join(base_dir, f"wg{instance.instance_id}.conf")

        os.makedirs(base_dir, exist_ok=True)

        with open(config_path, "w") as config_file:
            config_file.write(config_content)
    messages.success(request, "Export successful!|WireGuard configuration files have been exported to /etc/wireguard/. Don't forget to restart the interfaces.")
    if request.GET.get('action') == 'update_and_restart':
        return redirect('/tools/restart_wireguard/?action=dismiss_warning')
    return redirect('/status/')


@login_required
def download_config_or_qrcode(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=20).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    peer_uuid = request.GET.get('uuid')
    format_type = request.GET.get('format', 'conf')

    config_content = generate_peer_config(peer_uuid)

    if format_type == 'qrcode':
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(config_content)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        response = HttpResponse(content_type="image/png")
        img_io = BytesIO()
        img.save(img_io)
        img_io.seek(0)
        response.write(img_io.getvalue())

    else:
        response = HttpResponse(config_content, content_type="text/plain")
        response['Content-Disposition'] = f'attachment; filename="peer_{peer_uuid}.conf"'

    return response


@login_required
def restart_wireguard_interfaces(request):
    if not UserAcl.objects.filter(user=request.user).filter(user_level__gte=30).exists():
        return render(request, 'access_denied.html', {'page_title': 'Access Denied'})
    
    config_dir = "/etc/wireguard"
    interface_count = 0
    error_count = 0

    for filename in os.listdir(config_dir):
        if filename.endswith(".conf"):
            interface_name = filename[:-5]
            stop_command = f"wg-quick down {interface_name}"
            stop_result = subprocess.run(stop_command, shell=True, capture_output=True, text=True)
            if stop_result.returncode != 0:
                messages.warning(request, f"Error stopping {interface_name}|{stop_result.stderr}")
                error_count += 1
            start_command = f"wg-quick up {interface_name}"
            start_result = subprocess.run(start_command, shell=True, capture_output=True, text=True)
            if start_result.returncode != 0:
                messages.warning(request, f"Error starting {interface_name}|{start_result.stderr}")
                error_count += 1
            else:
                interface_count += 1

    if interface_count > 0 and error_count == 0:
        if interface_count == 1:
            messages.success(request, "Interface restarted|The WireGuard interface has been restarted.")
        else:
            messages.success(request, f"Interfaces restarted|{interface_count} WireGuard interfaces have been restarted.")
    elif error_count > 0:
        messages.warning(request, f"Errors encountered|There were errors restarting some interfaces. See warnings for details.")

    if interface_count == 0 and error_count == 0:
        messages.info(request, "No interfaces found|No WireGuard interfaces were found to restart.")
    if request.GET.get('action') == 'dismiss_warning':
        for wireguard_instancee in WireGuardInstance.objects.filter(pending_changes=True):
            wireguard_instancee.pending_changes = False
            wireguard_instancee.save()
    return redirect("/status/")

