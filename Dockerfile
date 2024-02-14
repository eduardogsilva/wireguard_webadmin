# Usar uma imagem base do Python
FROM python:3.10

# Definir o diretório de trabalho no container
WORKDIR /app

RUN apt-get update && apt-get install -y \
    wireguard \
    iptables \
    iproute2 \
    net-tools \
    inetutils-ping \
    inetutils-traceroute \
    nano \
    vim-nox \
    && rm -rf /var/lib/apt/lists/*

# those are the really necessary packages
#RUN apt-get update && apt-get install -y \
#    wireguard \
#    iptables \
#    && rm -rf /var/lib/apt/lists/*

# Copiar o arquivo requirements.txt para o container
COPY requirements.txt /app/

# Instalar as dependências do Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar o restante do código-fonte do projeto para o container
COPY . /app/

# Dar permissão de execução para o script init.sh
RUN chmod +x /app/init.sh

# Comando para executar o script init.sh
CMD ["/app/init.sh"]
