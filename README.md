## 🌍 Read this in other languages:
- 🇬🇧 [English](README.md)
- 🇧🇷 [Português](docs/README.pt-br.md)
- 🇪🇸 [Español](docs/README.es.md)
- 🇫🇷 [Français](docs/README.fr.md)
- 🇩🇪 [Deutsch](docs/README.de.md)

✨ If you find any issues with the translation or would like to request a new language, please open an [issue](https://github.com/eduardogsilva/wireguard_webadmin/issues).


# wireguard_webadmin

**Self-hosted VPN management and Zero Trust access control — all on your infrastructure.**

More than a WireGuard panel: manage peers, firewall rules, DNS, port forwarding, and publish internal apps with proper authentication — without relying on third-party services. Runs on any Linux machine with Docker. Free, open source, nothing leaves your server.

- ⚙️ **Manage** — Multiple WireGuard instances, peer traffic graphs, firewall, DNS blacklists, VPN invite links with QR code
- 🔒 **Protect** — Zero Trust application gateway with TOTP, IP ACL, and anti-brute-force (Altcha PoW)
- ⚡ **Automate** — Scheduled peer access, routing templates, expiring invite links, REST API v2

### 📖 Full documentation, installation guide and tips at [wireguard-webadmin.com](https://wireguard-webadmin.com/)

---

## Quick Install

```bash
mkdir wireguard_webadmin && cd wireguard_webadmin
wget -O docker-compose.yml https://raw.githubusercontent.com/eduardogsilva/wireguard_webadmin/main/docker-compose-caddy.yml
# edit .env with your SERVER_ADDRESS
docker compose up -d
```

> For detailed instructions, upgrade guide, and configuration tips visit **[wireguard-webadmin.com](https://wireguard-webadmin.com/)**.

---

## Screenshots

### Peer List
Real-time status and live bandwidth graphs for every peer across all WireGuard instances.
![Peer List](docs/images/peer_list_dark.png)

### Peer Details
Traffic history, last handshake, allowed IPs, and QR code — all in one place.
![Peer Details](docs/images/peer_details.png)

### Zero Trust Application Gateway
Publish internal apps like Proxmox or Grafana with TOTP authentication in front — no open ports needed.
![Zero Trust App Gateway](docs/images/zero_trust_app.png)

### Firewall Management
Per-instance iptables rules, port forwarding, and outbound ACLs managed from the UI.
![Firewall](docs/images/firewall.png)

### VPN Invite
Generate a shareable invite with QR code and config file. The user scans or imports it directly into their WireGuard client.
![VPN Invite](docs/images/vpn_invite.png)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome and greatly appreciated. Feel free to open issues or pull requests on [GitHub](https://github.com/eduardogsilva/wireguard_webadmin).
