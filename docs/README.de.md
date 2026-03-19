## 🌍 Lies das in anderen Sprachen:
- 🇬🇧 [English](../README.md)
- 🇧🇷 [Português](README.pt-br.md)
- 🇪🇸 [Español](README.es.md)
- 🇫🇷 [Français](README.fr.md)
- 🇩🇪 [Deutsch](README.de.md)

✨ Wenn dir bei der Übersetzung Fehler auffallen oder du eine neue Sprache anfordern möchtest, öffne bitte ein [Issue](https://github.com/eduardogsilva/wireguard_webadmin/issues).


# wireguard_webadmin

**Self-hosted VPN-Verwaltung und Zero-Trust-Zugangskontrolle — alles auf deiner eigenen Infrastruktur.**

Mehr als ein WireGuard-Panel: Verwalte Peers, Firewall-Regeln, DNS und Port-Weiterleitungen und veröffentliche interne Anwendungen mit echter Authentifizierung — ohne Abhängigkeit von Drittanbietern. Läuft auf jeder Linux-Maschine mit Docker. Kostenlos, open source, nichts verlässt deinen Server.

- ⚙️ **Verwalten** — Mehrere WireGuard-Instanzen, Traffic-Graphen pro Peer, Firewall, DNS-Blacklists, VPN-Einladungen mit QR-Code
- 🔒 **Schützen** — Zero-Trust-Anwendungs-Gateway mit TOTP, IP-ACL und Brute-Force-Schutz (Altcha PoW)
- ⚡ **Automatisieren** — Zeitgesteuerter Peer-Zugang, Routing-Templates, ablaufende Einladungslinks, REST API v2

### 📖 [Vollständige Dokumentation, Installationsanleitung und Tipps auf wireguard-webadmin.com](https://wireguard-webadmin.com/)

---

## Schnellinstallation

```bash
mkdir wireguard_webadmin && cd wireguard_webadmin
wget -O docker-compose.yml https://raw.githubusercontent.com/eduardogsilva/wireguard_webadmin/main/docker-compose-caddy.yml
# .env mit deiner SERVER_ADDRESS bearbeiten
docker compose up -d
```

> Für detaillierte Anleitungen, Upgrade-Guide und Konfigurationstipps besuche **[wireguard-webadmin.com](https://wireguard-webadmin.com/)**.

---

## Screenshots

### Peer-Liste
Echtzeit-Status und Live-Bandbreitengraphen für jeden Peer über alle WireGuard-Instanzen hinweg.
![Peer-Liste](images/peer_list_dark.png)

### Peer-Details
Traffic-Historie, letzter Handshake, erlaubte IPs und QR-Code — alles an einem Ort.
![Peer-Details](images/peer_details.png)

### Zero-Trust-Anwendungs-Gateway
Veröffentliche interne Apps wie Proxmox oder Grafana mit TOTP-Authentifizierung davor — ohne offene Ports.
![Zero-Trust-Gateway](images/zero_trust_app.png)

### Firewall-Verwaltung
iptables-Regeln pro Instanz, Port-Weiterleitungen und ausgehende ACLs direkt über die Oberfläche verwalten.
![Firewall](images/firewall.png)

### VPN-Einladung
Erstelle einen teilbaren Einladungslink mit QR-Code und Konfigurationsdatei. Der Nutzer scannt oder importiert ihn direkt in seinen WireGuard-Client.
![VPN-Einladung](images/vpn_invite.png)

---

## Lizenz

Dieses Projekt steht unter der MIT-Lizenz – siehe [LICENSE](../LICENSE) für Details.

## Beitragen

Beiträge sind willkommen und sehr geschätzt. Öffne gerne Issues oder Pull Requests auf [GitHub](https://github.com/eduardogsilva/wireguard_webadmin).
