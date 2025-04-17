## 🌍 Leia em outros idiomas:
- 🇬🇧 [English](../README.md)
- 🇧🇷 [Português](README.pt-br.md)
- 🇪🇸 [Español](README.es.md)
- 🇫🇷 [Français](README.fr.md)
- 🇩🇪 [Deutsch](README.de.md)

✨ Se encontrar algum problema na tradução ou quiser solicitar um novo idioma, por favor abra uma [issue](https://github.com/eduardogsilva/wireguard_webadmin/issues).

# wireguard_webadmin

**wireguard_webadmin** é uma interface web completa e fácil de configurar para gerenciar instâncias WireGuard VPN. Projetada para simplificar a administração de redes WireGuard, ela oferece uma interface amigável que suporta múltiplos usuários com diferentes níveis de acesso, várias instâncias WireGuard com gerenciamento individual de peers e suporte a *crypto‑key routing* para interconexões *site‑to‑site*.

## Funcionalidades

- **Histórico de Transferência de Cada Peer**: Acompanhe individualmente os volumes de download e upload de cada peer.
- **Gerenciamento Avançado de Firewall**: Experimente um gerenciamento de firewall de VPN abrangente e sem complicações, projetado para ser simples e eficaz.
- **Redirecionamento de Portas**: Redirecione portas TCP ou UDP para peers ou redes além desses peers com facilidade!
- **Servidor DNS**: Suporte a hosts personalizados e listas de bloqueio DNS para maior segurança e privacidade.
- **Suporte Multiusuário**: Gerencie o acesso com diferentes níveis de permissão para cada usuário.
- **Múltiplas Instâncias WireGuard**: Permite o gerenciamento separado de peers em várias instâncias.
- **Crypto‑Key Routing**: Simplifica a configuração de interconexões *site‑to‑site*.
- **Compartilhamento de Convites VPN Sem Atrito**: Gere e distribua instantaneamente convites VPN seguros e com tempo de validade via e‑mail ou WhatsApp, contendo QR code e arquivo de configuração.

Este projeto tem como objetivo oferecer uma solução intuitiva e fácil de usar para gerenciamento de VPN WireGuard sem comprometer o poder e a flexibilidade que o WireGuard oferece.

## Licença

Este projeto é licenciado sob a licença MIT – consulte o arquivo [LICENSE](../LICENSE) para detalhes.

## Capturas de Tela

### Lista de Peers
Exibe uma lista abrangente de peers, incluindo seu status e outros detalhes, permitindo monitorar e gerenciar facilmente as conexões VPN do WireGuard.
![Lista de Peers do WireGuard](../screenshots/peerlist.png)

### Detalhes do Peer
Mostra informações essenciais do peer, métricas detalhadas e um histórico completo de volume de tráfego. Inclui também um QR code para configuração fácil.
![Detalhes do Peer](../screenshots/peerinfo.png)

### Convite VPN
Gera convites VPN seguros e com tempo de validade para compartilhamento de configurações via e‑mail ou WhatsApp, com QR code e arquivo de configuração.
![Convite VPN](../screenshots/vpninvite.png)

### Filtragem DNS Avançada
Bloqueie conteúdo indesejado com listas de filtragem DNS integradas. Categorias predefinidas como pornografia, jogos de azar, fake news, adware e malware estão incluídas, com a possibilidade de adicionar categorias personalizadas para uma experiência de segurança sob medida.
![Servidor DNS](../screenshots/dns.png)

### Gerenciamento de Firewall
Oferece uma interface abrangente para gerenciar regras de firewall da VPN, permitindo criar, editar e excluir regras com sintaxe estilo *iptables*. Este recurso garante controle preciso do tráfego de rede, ampliando a segurança e a conectividade das instâncias WireGuard.
![Lista de Regras de Firewall](../screenshots/firewall-rule-list.png)
![Gerenciador de Regras de Firewall](../screenshots/firewall-manage-rule.png)

### Configurações da Instância WireGuard
Um hub central para gerenciar configurações de uma ou várias instâncias WireGuard, possibilitando ajustes de configuração de forma simples.
![Configuração do Servidor WireGuard](../screenshots/serverconfig.png)

### Console
Acesso rápido a ferramentas comuns de depuração, facilitando o diagnóstico e a resolução de possíveis problemas no ambiente VPN WireGuard.
![Console](../screenshots/console.png)

### Gerenciador de Usuários
Suporta ambientes multiusuário permitindo atribuir níveis de permissão variados, desde acesso restrito até direitos administrativos completos, garantindo controle de acesso seguro e personalizado.
![Gerenciador de Usuários](../screenshots/usermanager.png)

---

## Instruções de Implantação

Siga estes passos para implantar o WireGuard WebAdmin:

1. **Prepare o Ambiente:**

   Primeiro, crie um diretório para o projeto WireGuard WebAdmin e navegue até ele. Este será o diretório de trabalho para a implantação.

   ```bash
   mkdir wireguard_webadmin && cd wireguard_webadmin
   ```

2. **Obtenha o Arquivo Docker Compose:**

   Dependendo do seu cenário de implantação, escolha um dos comandos a seguir para baixar o arquivo `docker-compose.yml` apropriado diretamente no seu diretório de trabalho. Esse método garante que você está usando a versão mais recente da configuração de implantação.

   ### Com NGINX (Recomendado)

   Para uma implantação pronta para produção com NGINX como *reverse proxy* (recomendado para a maioria dos usuários), use:

   ```bash
   wget -O docker-compose.yml https://raw.githubusercontent.com/eduardogsilva/wireguard_webadmin/main/docker-compose.yml
   ```

   Este modo é recomendado para executar a interface web de administração. O *deployment* do contêiner gerará automaticamente um certificado autoassinado para você. Se desejar atualizar seus certificados, basta acessar o volume `certificates` e substituir `nginx.pem` e `nginx.key` pelos seus próprios certificados.

   ### Sem NGINX (Somente para Debug e Testes)

   Para um ambiente de depuração sem NGINX, adequado apenas para testes (não recomendado em produção), use:

   ```bash
   wget -O docker-compose.yml https://raw.githubusercontent.com/eduardogsilva/wireguard_webadmin/main/docker-compose-no-nginx.yml
   ```

3. **Crie o Arquivo `.env`:**

   Crie um arquivo `.env` no mesmo diretório do seu `docker-compose.yml` com o conteúdo abaixo, ajustando `my_server_address` para o DNS ou endereço IP do seu servidor. Este passo é crucial para garantir o funcionamento correto da aplicação.

   ```env
   # Configure SERVER_ADDRESS para coincidir com o endereço do servidor. Se não tiver um nome DNS, você pode usar o IP.
   # Um SERVER_ADDRESS configurado incorretamente causará erros de CSRF na aplicação.
   SERVER_ADDRESS=my_server_address
   DEBUG_MODE=False
   ```

   Substitua `my_server_address` pelo endereço real do seu servidor.

4. **Execute o Docker Compose:**

   ### Com NGINX (Recomendado)

   ```bash
   docker compose up -d
   ```

   Acesse a interface web em `https://seuservidor.exemplo.com`. Se estiver usando um certificado autoassinado, será necessário aceitar a exceção de certificado apresentada pelo navegador.

   ### Sem NGINX (Somente para Debug e Testes)

   Caso tenha optado pela configuração sem NGINX, simplesmente execute o arquivo `docker-compose-no-nginx.yml` obtido anteriormente:

   ```bash
   docker compose -f docker-compose-no-nginx.yml up -d
   ```

   Acesse a interface web em `http://127.0.0.1:8000`.

Após concluir esses passos, o WireGuard WebAdmin deverá estar em execução. Inicie a configuração acessando a interface web do seu servidor.

---

## Instruções de Upgrade

Manter sua instalação do WireGuard WebAdmin atualizada garante acesso aos recursos mais recentes, melhorias de segurança e correções de bugs. Siga estas instruções para um upgrade tranquilo:

### Preparação para o Upgrade:

1. **Transição de um Workflow *git clone*:**

   Navegue até o diretório `wireguard_webadmin`:

   ```bash
   cd path/to/wireguard_webadmin
   ```

   Se estiver atualizando a partir de uma instalação existente via *git clone*, navegue até o diretório do projeto atual.

   ```bash
   cd /path/to/wireguard_webadmin_git_clone
   ```

2. **Desligue os Serviços:**

   Pare todos os serviços em execução para evitar perda de dados durante o upgrade.

   ```bash
   docker compose down
   ```

3. **Baixe as Imagens Mais Recentes:**

   Atualize suas imagens locais:

   ```bash
   docker compose pull
   ```

4. **Faça Backup dos Seus Dados:**

   Antes de qualquer alteração, faça backup do banco de dados e de outros dados importantes. Este passo é essencial para restaurar sua configuração, se necessário.

   ```bash
   tar cvfz wireguard-webadmin-backup-$(date +%Y-%m-%d-%H%M%S).tar.gz /var/lib/docker/volumes/wireguard_webadmin_wireguard/_data/
   ```

   Substitua `/var/lib/docker/volumes/wireguard_webadmin_wireguard/_data/` pelo caminho real do volume Docker, se diferente. O comando salva o backup no diretório atual.

5. **Implante Usando Docker Compose:**

   Siga as [Instruções de Implantação](#instruções-de-implantação) descritas anteriormente.

> **Observação:** Não se esqueça de atualizar o arquivo `docker-compose.yml` para a versão mais recente, baixando-o novamente do repositório.

### Verificações Pós‑Upgrade:

- **Verifique a Operação:** Após iniciar os serviços, acesse a interface web para garantir que o WireGuard WebAdmin esteja funcionando como esperado. Examine os logs da aplicação para possíveis problemas.
- **Suporte e Solução de Problemas:** Em caso de complicações ou para mais informações, consulte a página de [Discussions](https://github.com/eduardogsilva/wireguard_webadmin/discussions) do projeto ou a documentação pertinente.

Seguindo estas instruções, você atualizará seu WireGuard WebAdmin para a versão mais recente, incorporando todas as melhorias e atualizações de segurança disponíveis. Lembre‑se, backups regulares e o cumprimento destes passos de upgrade ajudam a manter a saúde e a segurança da sua implantação.

---

## Contribuindo

Contribuições tornam a comunidade *open‑source* um lugar incrível para aprender, inspirar e criar. Suas contribuições são **muito bem‑vindas**.

## Suporte

Se encontrar qualquer problema ou precisar de assistência, abra uma *issue* na página GitHub do projeto.
