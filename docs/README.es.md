## 🌍 Lea esto en otros idiomas:
- 🇬🇧 [English](../README.md)
- 🇧🇷 [Português](README.pt-br.md)
- 🇪🇸 [Español](README.es.md)
- 🇫🇷 [Français](README.fr.md)
- 🇩🇪 [Deutsch](README.de.md)

✨ Si encuentra algún problema con la traducción o desea solicitar un nuevo idioma, por favor abra un [issue](https://github.com/eduardogsilva/wireguard_webadmin/issues).

# wireguard_webadmin

**wireguard_webadmin** es una interfaz web completa y fácil de configurar para administrar instancias de WireGuard VPN. Diseñada para simplificar la administración de redes WireGuard, ofrece una interfaz intuitiva que admite múltiples usuarios con distintos niveles de acceso, varias instancias de WireGuard con gestión individual de peers y soporte para *crypto‑key routing* en interconexiones *site‑to‑site*.

## Funcionalidades

- **Historial de Transferencia por Peer**: Controle los volúmenes de descarga y subida de cada peer individualmente.
- **Gestión Avanzada de Firewall**: Disfrute de una gestión de firewall de VPN integral y sencilla, diseñada para ser eficaz.
- **Redirección de Puertos**: Redirija puertos TCP o UDP a peers o redes detrás de esos peers con facilidad.
- **Servidor DNS**: Soporte para hosts personalizados y listas de bloqueo DNS para mayor seguridad y privacidad.
- **Soporte Multiusuario**: Gestione el acceso con diferentes niveles de permisos para cada usuario.
- **Múltiples Instancias de WireGuard**: Permite la gestión separada de peers en varias instancias.
- **Crypto‑Key Routing**: Simplifica la configuración de interconexiones *site‑to‑site*.
- **Compartir Invitaciones VPN Sin Esfuerzo**: Genere y distribuya al instante invitaciones VPN seguras y temporales por correo electrónico o WhatsApp, con código QR y archivo de configuración.

Este proyecto tiene como objetivo ofrecer una solución intuitiva y fácil de usar para la gestión de VPN WireGuard sin comprometer la potencia y flexibilidad que proporciona WireGuard.

## Licencia

Este proyecto está bajo la licencia MIT. Consulte el archivo [LICENSE](../LICENSE) para más detalles.

## Capturas de Pantalla

### Lista de Peers
Muestra una lista completa de peers, incluido su estado y otros detalles, lo que permite supervisar y gestionar fácilmente las conexiones VPN de WireGuard.
![Lista de Peers de WireGuard](../screenshots/peerlist.png)

### Detalles del Peer
Presenta información clave del peer, métricas detalladas y un historial completo de volumen de tráfico. También incluye un código QR para una configuración sencilla.
![Detalles del Peer](../screenshots/peerinfo.png)

### Invitación VPN
Genera invitaciones VPN seguras y temporales para compartir fácilmente la configuración por correo electrónico o WhatsApp, con código QR y archivo de configuración.
![Invitación VPN](../screenshots/vpninvite.png)

### Filtrado DNS Avanzado
Bloquee contenido no deseado mediante listas de filtrado DNS integradas. Incluye categorías predefinidas como pornografía, juegos de azar, noticias falsas, adware y malware, con la posibilidad de agregar categorías personalizadas para una experiencia de seguridad adaptada.
![Servidor DNS](../screenshots/dns.png)

### Gestión de Firewall
Proporciona una interfaz completa para gestionar reglas de firewall de la VPN, permitiendo crear, editar y eliminar reglas con sintaxis estilo *iptables*. Esta característica garantiza un control preciso del tráfico de red, mejorando la seguridad y la conectividad de las instancias de WireGuard.
![Lista de Reglas de Firewall](../screenshots/firewall-rule-list.png)
![Gestor de Reglas de Firewall](../screenshots/firewall-manage-rule.png)

### Configuración de Instancias de WireGuard
Un centro de control para gestionar la configuración de una o varias instancias de WireGuard, permitiendo ajustes sencillos de la VPN.
![Configuración del Servidor WireGuard](../screenshots/serverconfig.png)

### Consola
Acceso rápido a herramientas comunes de depuración, lo que facilita el diagnóstico y la resolución de posibles problemas en el entorno VPN WireGuard.
![Consola](../screenshots/console.png)

### Gestor de Usuarios
Admite entornos multiusuario permitiendo asignar distintos niveles de permisos, desde acceso restringido hasta derechos administrativos completos, garantizando un control de acceso seguro y personalizado.
![Gestor de Usuarios](../screenshots/usermanager.png)

---

## Instrucciones de Despliegue

Siga estos pasos para desplegar WireGuard WebAdmin:

1. **Prepare el Entorno:**

   Cree un directorio para el proyecto WireGuard WebAdmin y acceda a él. Este será el directorio de trabajo para el despliegue.

   ```bash
   mkdir wireguard_webadmin && cd wireguard_webadmin
   ```

2. **Obtenga el Archivo Docker Compose:**

   Según su escenario de despliegue, elija uno de los siguientes comandos para descargar el archivo `docker-compose.yml` correspondiente directamente en su directorio de trabajo. Este método garantiza que utilice la versión más reciente de la configuración.

   ### Con NGINX (Recomendado)

   Para un despliegue de producción con NGINX como *reverse proxy* (recomendado para la mayoría), use:

   ```bash
   wget -O docker-compose.yml https://raw.githubusercontent.com/eduardogsilva/wireguard_webadmin/main/docker-compose.yml
   ```

   Este modo es el recomendado para ejecutar la interfaz web de administración. El despliegue del contenedor generará automáticamente un certificado autofirmado. Si desea actualizar sus certificados, acceda al volumen `certificates` y sustituya `nginx.pem` y `nginx.key` por sus propios certificados.

   ### Sin NGINX (Solo para Depuración y Pruebas)

   Para un entorno de depuración sin NGINX (no recomendado en producción), use:

   ```bash
   wget -O docker-compose.yml https://raw.githubusercontent.com/eduardogsilva/wireguard_webadmin/main/docker-compose-no-nginx.yml
   ```

3. **Cree el Archivo `.env`:**

   Cree un archivo `.env` en el mismo directorio que su `docker-compose.yml` con el siguiente contenido, ajustando `my_server_address` al nombre DNS o IP de su servidor.

   ```env
   # Configure SERVER_ADDRESS para que coincida con la dirección de su servidor. Puede usar la IP si no tiene DNS.
   # Una SERVER_ADDRESS mal configurada provocará errores CSRF.
   SERVER_ADDRESS=my_server_address
   DEBUG_MODE=False
   ```

   Sustituya `my_server_address` por la dirección real de su servidor.

4. **Ejecute Docker Compose:**

   ### Con NGINX (Recomendado)

   ```bash
   docker compose up -d
   ```

   Acceda a la interfaz web en `https://suserver.ejemplo.com`. Si utiliza un certificado autofirmado, acepte la excepción de seguridad en su navegador.

   ### Sin NGINX (Solo para Depuración y Pruebas)

   Si eligió la configuración sin NGINX, ejecute el archivo descargado `docker-compose-no-nginx.yml`:

   ```bash
   docker compose -f docker-compose-no-nginx.yml up -d
   ```

   Acceda a la interfaz en `http://127.0.0.1:8000`.

Tras completar estos pasos, WireGuard WebAdmin estará en funcionamiento. Comience la configuración accediendo a la interfaz web de su servidor.

---

## Instrucciones de Actualización

Actualizar su instalación de WireGuard WebAdmin garantiza acceso a nuevas funciones, mejoras de seguridad y correcciones. Siga estas instrucciones para una actualización sin problemas:

### Preparación para la Actualización:

1. **Transición desde un flujo de trabajo *git clone*:**

   Acceda al directorio `wireguard_webadmin`:

   ```bash
   cd path/to/wireguard_webadmin
   ```

   Si actualiza desde una instalación realizada con *git clone*, vaya al directorio del proyecto:

   ```bash
   cd /path/to/wireguard_webadmin_git_clone
   ```

2. **Detenga los Servicios:**

   Pare todos los servicios para evitar pérdida de datos durante la actualización.

   ```bash
   docker compose down
   ```

3. **Descargue las Imágenes Más Recientes:**

   Actualice sus imágenes locales:

   ```bash
   docker compose pull
   ```

4. **Haga Copia de Seguridad de Sus Datos:**

   Antes de cualquier cambio, realice una copia de seguridad de la base de datos y de datos importantes.

   ```bash
   tar cvfz wireguard-webadmin-backup-$(date +%Y-%m-%d-%H%M%S).tar.gz /var/lib/docker/volumes/wireguard_webadmin_wireguard/_data/
   ```

   Sustituya la ruta del volumen Docker si es diferente. El archivo se guardará en el directorio actual.

5. **Despliegue con Docker Compose:**

   Siga las [Instrucciones de Despliegue](#instrucciones-de-despliegue) indicadas anteriormente.

> **Nota:** No olvide actualizar `docker-compose.yml` a la versión más reciente descargándolo de nuevo del repositorio.

### Verificaciones Posteriores a la Actualización:

- **Verifique el Funcionamiento:** Una vez iniciados los servicios, acceda a la interfaz web para comprobar que WireGuard WebAdmin funciona correctamente. Revise los registros de la aplicación para detectar problemas.
- **Soporte y Solución de Problemas:** Si surge alguna complicación, consulte la sección de [Discussions](https://github.com/eduardogsilva/wireguard_webadmin/discussions) o la documentación relacionada.

Siguiendo estos pasos, actualizará WireGuard WebAdmin a la versión más reciente, incorporando todas las mejoras y correcciones de seguridad. Recuerde que realizar copias de seguridad periódicas y seguir estos pasos ayuda a mantener la salud y seguridad de su implementación.

---

## Contribuir

Las contribuciones hacen que la comunidad *open‑source* sea un lugar increíble para aprender, inspirar y crear. Sus contribuciones son **muy apreciadas**.

## Soporte

Si encuentra problemas o necesita ayuda, abra un *issue* en la página de GitHub del proyecto.

