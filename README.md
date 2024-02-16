
# wireguard_webadmin

wireguard_webadmin is a full-featured yet easy-to-configure web interface for managing WireGuard VPN instances. Designed to simplify the administration of WireGuard networks, it provides a user-friendly interface that supports multiple users with varying access levels, multiple WireGuard instances with individual peer management, and support for crypto key routing for site-to-site interconnections.

## Features

- **Multi-User Support**: Manage access with different permission levels for each user.
- **Multiple WireGuard Instances**: Enables separate management for peers across multiple instances.
- **Crypto Key Routing**: Simplifies the configuration for site-to-site interconnections.

This project aims to offer an intuitive and user-friendly solution for WireGuard VPN management without compromising the power and flexibility WireGuard provides.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Deployment

Follow these steps to deploy wireguard_webadmin:

1. Clone the repository:
   ```
   git clone https://github.com/eduardogsilva/wireguard_webadmin
   ```

2. Create the `wireguard_webadmin/production_settings.py` file and configure the minimum required variables:
   ```python
   DEBUG = False
   ALLOWED_HOSTS = ['your_domain']
   CSRF_TRUSTED_ORIGINS = ['https://your_domain']
   SECRET_KEY = 'your_secret_key'
   ```

3. Place your SSL certificates for nginx in the `certificates` volume.

4. Run Docker Compose:
   ```
   docker-compose up
   ```

After completing these steps, your wireguard_webadmin should be up and running. Access your server using `http://your_domain` and start configuring it.

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

## Support

If you encounter any issues or require assistance, please open an issue on the project's GitHub page.
