# wireguard_webadmin

wireguard_webadmin is a full-featured yet easy-to-configure web interface for managing WireGuard VPN instances. Designed to simplify the administration of WireGuard networks, it provides a user-friendly interface that supports multiple users with varying access levels, multiple WireGuard instances with individual peer management, and support for crypto key routing for site-to-site interconnections.

## Features

- **Multi-User Support**: Manage access with different permission levels for each user.
- **Multiple WireGuard Instances**: Enables separate management for peers across multiple instances.
- **Crypto Key Routing**: Simplifies the configuration for site-to-site interconnections.

This project aims to offer an intuitive and user-friendly solution for WireGuard VPN management without compromising the power and flexibility WireGuard provides.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Screenshots

![Wireguard Peer List](screenshots/peerlist.png) ![Wireguard Server Configuration](screenshots/serverconfig.png) ![Console](screenshots/console.png) ![User Manager](screenshots/usermanager.png)

## Deployment

Follow these steps to deploy wireguard_webadmin:

1. **Clone the repository:**
   ```
   git clone https://github.com/eduardogsilva/wireguard_webadmin
   ```

2. **Place your SSL certificates for nginx in the `certificates` volume.**
   The files should be named `nginx.pem` and `nginx.key`. You can use self-signed certificates and accept the certificate exception in your browser.

3. **Run Docker Compose (choose one):**

   ### With NGINX (Recommended)
   This mode is recommended for running the webadmin. Set up your certificates for nginx; you can use a self-signed certificate. If you don't have a DNS name pointing to your server, use `SERVER_ADDRESS=ip_address`.

   ```
   SERVER_ADDRESS=yourserver.example.com docker-compose up --build -d
   ```
   Access the web interface using `https://yourserver.example.com`.

   ### Without NGINX (Debug mode and testing only)
   This mode does not require SSL certificates and runs Django with `DEBUG=True`. Not recommended for production use without HTTPS.
   ```
   docker-compose -f docker-compose-no-nginx.yml up --build -d
   ```
   Access the web interface using `http://127.0.0.1:8000`.

After completing these steps, your wireguard_webadmin should be up and running. Begin configuration by accessing your server.

## Contributing

Contributions make the open-source community an amazing place to learn, inspire, and create. Your contributions are **greatly appreciated**.

## Support

If you encounter any issues or require assistance, please open an issue on the project's GitHub page.
