## 🌍 Lire ceci dans d'autres langues:
- 🇬🇧 [English](../README.md)
- 🇧🇷 [Português](README.pt-br.md)
- 🇪🇸 [Español](README.es.md)
- 🇫🇷 [Français](README.fr.md)
- 🇩🇪 [Deutsch](README.de.md)

✨ Si vous constatez un problème dans la traduction ou souhaitez demander une nouvelle langue, veuillez ouvrir une [issue](https://github.com/eduardogsilva/wireguard_webadmin/issues).


# wireguard_webadmin

**Gestion de VPN self-hosted et contrôle d'accès Zero Trust — entièrement sur votre infrastructure.**

Plus qu'un simple panneau WireGuard : gérez les pairs, les règles de pare-feu, le DNS, la redirection de ports et publiez des applications internes avec une authentification appropriée — sans dépendre de services tiers. Fonctionne sur n'importe quelle machine Linux avec Docker. Gratuit, open source, rien ne quitte votre serveur.

- ⚙️ **Gérer** — Plusieurs instances WireGuard, graphiques de trafic par pair, pare-feu, listes de blocage DNS, invitations VPN avec QR code
- 🔒 **Protéger** — Passerelle d'applications Zero Trust avec TOTP, ACL par IP et anti-force-brute (Altcha PoW)
- ⚡ **Automatiser** — Accès planifié par pair, modèles de routage, liens d'invitation avec expiration, API REST v2

### 📖 Documentation complète, guide d'installation et conseils sur [wireguard-webadmin.com](https://wireguard-webadmin.com/)

---

## Installation Rapide

```bash
mkdir wireguard_webadmin && cd wireguard_webadmin
wget -O docker-compose.yml https://raw.githubusercontent.com/eduardogsilva/wireguard_webadmin/main/docker-compose-caddy.yml
# éditez .env avec votre SERVER_ADDRESS
docker compose up -d
```

> Pour des instructions détaillées, un guide de mise à jour et des conseils de configuration, visitez **[wireguard-webadmin.com](https://wireguard-webadmin.com/)**.

---

## Captures d'écran

### Liste des pairs
Statut en temps réel et graphiques de bande passante en direct pour chaque pair sur toutes les instances WireGuard.
![Liste des pairs](images/peer_list_dark.png)

### Détails d'un pair
Historique du trafic, dernier handshake, IPs autorisées et QR code — le tout au même endroit.
![Détails d'un pair](images/peer_details.png)

### Passerelle d'applications Zero Trust
Publiez des applications internes comme Proxmox ou Grafana avec une authentification TOTP devant — sans ouvrir de ports.
![Passerelle Zero Trust](images/zero_trust_app.png)

### Gestion du pare-feu
Règles iptables par instance, redirection de ports et ACLs sortantes gérées depuis l'interface.
![Pare-feu](images/firewall.png)

### Invitation VPN
Générez un lien d'invitation avec QR code et fichier de configuration. L'utilisateur le scanne ou l'importe directement dans son client WireGuard.
![Invitation VPN](images/vpn_invite.png)

---

## Licence

Ce projet est distribué sous licence MIT – consultez le fichier [LICENSE](../LICENSE) pour plus de détails.

## Contribuer

Les contributions sont les bienvenues et très appréciées. N'hésitez pas à ouvrir des issues ou des pull requests sur [GitHub](https://github.com/eduardogsilva/wireguard_webadmin).
