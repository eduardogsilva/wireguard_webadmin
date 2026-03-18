## 🌍 Lies das in anderen Sprachen:
- 🇬🇧 [English](../README.md)
- 🇧🇷 [Português](README.pt-br.md)
- 🇪🇸 [Español](README.es.md)
- 🇫🇷 [Français](README.fr.md)
- 🇩🇪 [Deutsch](README.de.md)

✨ Wenn dir bei der Übersetzung Fehler auffallen oder du eine neue Sprache anfordern möchtest, öffne bitte ein [Issue](https://github.com/eduardogsilva/wireguard_webadmin/issues).

# wireguard_webadmin

**wireguard_webadmin** ist eine funktionsreiche und dennoch einfach zu konfigurierende Weboberfläche zur Verwaltung von WireGuard‑VPN‑Instanzen. Das Tool wurde entwickelt, um die Administration von WireGuard‑Netzwerken zu vereinfachen und bietet eine benutzerfreundliche Oberfläche mit Unterstützung für:

- mehrere Benutzer mit unterschiedlichen Berechtigungsstufen,
- mehrere WireGuard‑Instanzen mit individueller Peer‑Verwaltung sowie
- Crypto‑Key‑Routing für Site‑to‑Site‑Verbindungen.

## Funktionen

- **Individuelle Transferhistorie pro Peer**: Verfolge Upload‑ und Download‑Volumen jedes einzelnen Peers.
- **Erweiterte Firewall‑Verwaltung**: Mühelose, umfassende Verwaltung der VPN‑Firewall – konzipiert für Einfachheit und Effektivität.
- **Portweiterleitung**: Leite TCP‑ oder UDP‑Ports bequem an Peers oder an Netzwerke hinter diesen Peers weiter.
- **DNS‑Server**: Benutzerdefinierte Hosts und DNS‑Blacklists für höhere Sicherheit und verbesserten Datenschutz.
- **Mehrbenutzer‑Unterstützung**: Verwalte den Zugriff mit unterschiedlichen Berechtigungsstufen für jeden Benutzer.
- **Mehrere WireGuard‑Instanzen**: Separate Verwaltung der Peers über mehrere Instanzen hinweg.
- **Crypto‑Key‑Routing**: Vereinfacht die Konfiguration von Site‑to‑Site‑Verbindungen.
- **Einfaches Teilen von VPN‑Einladungen**: Erzeuge und verteile sofort sichere, zeitlich begrenzte VPN‑Einladungen per E‑Mail oder WhatsApp – inklusive QR‑Code und Konfigurationsdatei.
- **Routing-Vorlagen pro Peer**: Definieren Sie wiederverwendbare Routing-Vorlagen pro WireGuard-Instanz und wenden Sie diese auf Peers an, um ein konsistentes und vorhersehbares Routing-Verhalten zu gewährleisten.
- **Routenzwang mit automatischen Firewall-Regeln**: Erwingen Sie Routing-Richtlinien durch automatisches Erstellen von Firewall-Regeln, die Peers auf explizit erlaubte Routen beschränken.

Dieses Projekt zielt darauf ab, eine intuitive und benutzerfreundliche Lösung für das WireGuard‑Management bereitzustellen, ohne die Flexibilität und Leistung von WireGuard einzuschränken.

## Lizenz

Dieses Projekt steht unter der MIT‑Lizenz – siehe [LICENSE](../LICENSE) für Details.

## Screenshots

### Peer‑Liste
Zeigt eine vollständige Liste der Peers inklusive Status und weiterer Details zur einfachen Überwachung und Verwaltung von WireGuard‑Verbindungen.
![WireGuard Peer List](../screenshots/peerlist.png)

### Peer‑Details
Zeigt wichtige Peer‑Informationen, detaillierte Metriken sowie eine vollständige Traffic‑Historie. Enthält außerdem einen QR‑Code für die einfache Konfiguration.
![WireGuard Peer Details](../screenshots/peerinfo.png)

### VPN‑Einladung
Erstellt sichere, zeitlich begrenzte VPN‑Einladungen zum einfachen Teilen per E‑Mail oder WhatsApp – inklusive QR‑Code und Konfigurationsdatei.
![VPN Invite](../screenshots/vpninvite.png)

### Erweiterte DNS‑Filterung
Blockiere unerwünschte Inhalte mit integrierten DNS‑Filterlisten. Vorgefertigte Kategorien wie Pornografie, Glücksspiel, Fake‑News, Adware und Malware sind enthalten; eigene Kategorien lassen sich hinzufügen, um die Sicherheit anzupassen.
![DNS Server](../screenshots/dns.png)

### Firewall‑Verwaltung
Bietet eine umfassende Oberfläche zur Verwaltung von VPN‑Firewall‑Regeln. Regeln können mit iptables‑ähnlicher Syntax erstellt, bearbeitet und gelöscht werden und ermöglichen so eine präzise Steuerung des Datenverkehrs.
![Firewall Rule List](../screenshots/firewall-rule-list.png)
![Firewall Rule Manager](../screenshots/firewall-manage-rule.png)

### WireGuard‑Instanz‑Einstellungen
Zentrale Anlaufstelle für die Verwaltung der Einstellungen einer oder mehrerer WireGuard‑Instanzen.
![WireGuard Server Configuration](../screenshots/serverconfig.png)

### Konsole
Schneller Zugriff auf häufig genutzte Debugging‑Tools zur Diagnose und Lösung potenzieller Probleme in der WireGuard‑Umgebung.
![Console](../screenshots/console.png)

### Benutzerverwaltung
Unterstützt Mehrbenutzer‑Umgebungen durch Zuweisung unterschiedlicher Berechtigungsstufen – von eingeschränktem Zugriff bis hin zu vollständigen Administratorrechten.
![User Manager](../screenshots/usermanager.png)

Auf Basis deiner Anforderungen wurden die folgenden Deploy‑Anweisungen erstellt. Sie verwenden `wget`, um stets die aktuellste `docker-compose.yml` direkt aus deinem GitHub‑Repository abzurufen, und erläutern die Erstellung einer `.env`‑Datei für Umgebungsvariablen. So stellst du sicher, dass Nutzer immer mit der neuesten Deployment‑Konfiguration arbeiten.

## Deploy‑Anleitung

Folge diesen Schritten, um WireGuard WebAdmin bereitzustellen:

1. **Umgebung vorbereiten**

   Erstelle zunächst ein Verzeichnis für WireGuard WebAdmin und wechsle hinein:

   ```bash
   mkdir wireguard_webadmin && cd wireguard_webadmin
   ```

2.  **Docker‑Compose‑Datei herunterladen**

    Wähle je nach Szenario einen der folgenden Befehle, um die passende Compose-Datei herunterzuladen. So nutzt du stets die aktuelle Version der Deployment-Datei.

    ### Option 1: Mit Caddy (empfohlen)

    Für das empfohlene produktive Deployment mit Caddy als Reverse-Proxy:

    ```bash
    wget -O docker-compose.yml https://raw.githubusercontent.com/eduardogsilva/wireguard_webadmin/main/docker-compose-caddy.yml
    ```

    Dies ist die empfohlene Methode zum Betrieb der Web-Administrationsoberfläche, da sie alle unterstützten Reverse-Proxy-Funktionen umfasst und eine automatische SSL-Zertifikatsverwaltung über Caddy bietet.

> [!IMPORTANT]
> Caddy benötigt einen gültigen DNS-Namen, intern oder öffentlich, der auf Ihren Server zeigt, damit SSL-Zertifikate korrekt ausgestellt und erneuert werden können.

    ### Option 2: Ohne Caddy

    Wenn Sie Ihren eigenen Reverse-Proxy verwenden oder die Anwendung ohne Caddy betreiben möchten, nutzen Sie:

    ```bash
    wget -O docker-compose.yml https://raw.githubusercontent.com/eduardogsilva/wireguard_webadmin/main/docker-compose-no-caddy.yml
    ```

> [!CAUTION]
> Wenn Sie die Anwendung ohne Caddy betreiben, verlieren Sie die integrierte sichere Veröffentlichung, einschließlich automatischer SSL-Zertifikate und des empfohlenen Reverse-Proxy-Setups. Wenn Sie diese Option wählen, müssen Sie selbst für eine sichere Veröffentlichung sorgen.

3.  **.env‑Datei erstellen**

    Erstelle eine `.env`‑Datei im selben Verzeichnis wie deine `docker-compose.yml` und passe `my_server_address` an die DNS‑Adresse oder IP deines Servers an:

    ```env
    # SERVER_ADDRESS muss auf den Server zeigen. Ohne DNS‑Namen kann die IP genutzt werden.
    # Ein falsch konfigurierter SERVER_ADDRESS führt zu CSRF‑Fehlern.
    SERVER_ADDRESS=my_server_address
    DEBUG_MODE=False

    # Wähle eine Zeitzone aus https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
    TIMEZONE=Europe/Berlin

    # WireGuard‑Status‑Caching‑Einstellungen
    # Dies verbessert die Leistung, indem die Anzahl der Aufrufe des `wg`-Befehls reduziert und aktuelle Ergebnisse gespeichert werden.
    # WIREGUARD_STATUS_CACHE_ENABLED=True
    #
    # Wie viele zwischengespeicherte WireGuard-Status-Snapshots beim Laden der Seite vorgeladen werden sollen.
    # Dies ermöglicht es, dass Traffic-Diagramme bereits ausgefüllt angezeigt werden, anstatt leer zu beginnen.
    # Verringern Sie diesen Wert, wenn sich die initiale Peer-Liste langsam anfühlt.
    # 0 = Vorladen deaktivieren, 9 = Traffic-Diagramme vollständig ausfüllen.
    # WIREGUARD_STATUS_CACHE_WEB_LOAD_PREVIOUS_COUNT=9
    #
    # Wie oft (in Sekunden) der Cache aktualisiert werden soll.
    # Erlaubte Werte: 30, 60, 150, 300. Standard: 60.
    # WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL=60

    # Wenn Sie zusätzliche erlaubte Hosts benötigen, können Sie diese hier angeben.
    # Die SERVER_ADDRESS wird immer erlaubt sein.
    # Beispiel: EXTRA_ALLOWED_HOSTS=app1.beispiel.com,app2.beispiel.com:8443,app3.beispiel.com
    #EXTRA_ALLOWED_HOSTS=app1.beispiel.com,app2.beispiel.com:8443,app3.beispiel.com
    ```

4.  **Docker Compose ausführen**
 
    Führen Sie den Docker Compose-Befehl aus, um Ihr Deployment zu starten:

    ```bash
    docker compose up -d
    ```
 
    Öffnen Sie die Weboberfläche unter `https://yourserver.example.com`. Beim empfohlenen Deployment mit Caddy werden SSL-Zertifikate automatisch ausgestellt und erneuert.

Nach diesen Schritten sollte WireGuard WebAdmin laufen. Konfiguriere anschließend deine Instanzen über das Web‑Interface.

## Upgrade‑Anleitung

Regelmäßige Upgrades stellen sicher, dass du die neuesten Funktionen, Sicherheitsverbesserungen und Bugfixes erhältst.

### Vorbereitung

 1. **In das Projektverzeichnis wechseln**
 
    ```bash
    cd wireguard_webadmin
    ```

2. **Dienste stoppen**

   ```bash
   docker compose down
   ```

3. **Aktuelle Images ziehen**

   ```bash
   docker compose pull
   ```

4. **Daten sichern**

   ```bash
   tar cvfz wireguard-webadmin-backup-$(date +%Y-%m-%d-%H%M%S).tar.gz /var/lib/docker/volumes/wireguard_webadmin_wireguard/_data/
   ```

   Passe den Pfad zum Volume ggf. an.

5. **Neu deployen**

   Folge anschließend der [Deploy‑Anleitung](#deploy-anleitung) und lade dabei die aktuelle `docker-compose.yml` erneut herunter.

### Nach dem Upgrade

- **Funktion prüfen**: Web‑Interface aufrufen und Logs prüfen.
- **Unterstützung**: Bei Problemen siehe [Discussions](https://github.com/eduardogsilva/wireguard_webadmin/discussions).

## Beitragen

Beiträge machen die Open‑Source‑Community großartig. **Danke für jede Unterstützung!**

## Support

Bei Fragen oder Problemen eröffne bitte ein Issue auf GitHub.
