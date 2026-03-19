## 🌍 Lea esto en otros idiomas:
- 🇬🇧 [English](../README.md)
- 🇧🇷 [Português](README.pt-br.md)
- 🇪🇸 [Español](README.es.md)
- 🇫🇷 [Français](README.fr.md)
- 🇩🇪 [Deutsch](README.de.md)

✨ Si encuentra algún problema con la traducción o desea solicitar un nuevo idioma, por favor abra un [issue](https://github.com/eduardogsilva/wireguard_webadmin/issues).


# wireguard_webadmin

**Gestión de VPN self-hosted y control de acceso Zero Trust — todo en tu infraestructura.**

Más que un panel de WireGuard: gestiona peers, reglas de firewall, DNS, redirección de puertos y publica aplicaciones internas con autenticación adecuada — sin depender de servicios de terceros. Funciona en cualquier máquina Linux con Docker. Gratuito, open source, nada sale de tu servidor.

- ⚙️ **Gestionar** — Múltiples instancias WireGuard, gráficos de tráfico por peer, firewall, listas de bloqueo DNS, invitaciones VPN con código QR
- 🔒 **Proteger** — Gateway de aplicaciones Zero Trust con TOTP, ACL por IP y anti-fuerza-bruta (Altcha PoW)
- ⚡ **Automatizar** — Acceso programado por peer, plantillas de enrutamiento, enlaces de invitación con expiración, API REST v2

### 📖 [Documentación completa, guía de instalación y consejos en wireguard-webadmin.com](https://wireguard-webadmin.com/)

---

## Instalación Rápida

```bash
mkdir wireguard_webadmin && cd wireguard_webadmin
wget -O docker-compose.yml https://raw.githubusercontent.com/eduardogsilva/wireguard_webadmin/main/docker-compose-caddy.yml
# edite .env con su SERVER_ADDRESS
docker compose up -d
```

> Para instrucciones detalladas, guía de actualización y consejos de configuración visite **[wireguard-webadmin.com](https://wireguard-webadmin.com/)**.

---

## Capturas de Pantalla

### Lista de Peers
Estado en tiempo real y gráficos de ancho de banda en vivo para cada peer en todas las instancias WireGuard.
![Lista de Peers](images/peer_list_dark.png)

### Detalles del Peer
Historial de tráfico, último handshake, IPs permitidas y código QR — todo en un solo lugar.
![Detalles del Peer](images/peer_details.png)

### Gateway de Aplicaciones Zero Trust
Publique apps internas como Proxmox o Grafana con autenticación TOTP por delante — sin abrir puertos.
![Gateway Zero Trust](images/zero_trust_app.png)

### Gestión de Firewall
Reglas iptables por instancia, redirección de puertos y ACLs de salida gestionados desde la interfaz.
![Firewall](images/firewall.png)

### Invitación VPN
Genere un enlace de invitación con código QR y archivo de configuración. El usuario lo escanea o importa directamente en su cliente WireGuard.
![Invitación VPN](images/vpn_invite.png)

---

## Licencia

Este proyecto está bajo la licencia MIT. Consulte el archivo [LICENSE](../LICENSE) para más detalles.

## Contribuir

Las contribuciones son bienvenidas y muy apreciadas. No dude en abrir issues o pull requests en [GitHub](https://github.com/eduardogsilva/wireguard_webadmin).
