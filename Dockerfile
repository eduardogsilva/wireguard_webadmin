# Usar uma imagem base do Python
FROM python:3.10

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
    openssl \
    && rm -rf /var/lib/apt/lists/*

# those are the really necessary packages
#RUN apt-get update && apt-get install -y \
#    wireguard \
#    iptables \
#    openssl \
#    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

RUN chmod +x /app/init.sh
RUN chmod +x /app/entrypoint.sh
ARG SERVER_ADDRESS
ARG DEBUG_MODE
ENTRYPOINT ["/app/entrypoint.sh"]

CMD ["/app/init.sh"]
