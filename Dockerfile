# Build stage: install build dependencies and Python packages
FROM python:3.12-slim AS builder
WORKDIR /app

# Install build dependencies required for compiling C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    librrd-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python packages to a separate directory
COPY requirements.txt /app/
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

# Final stage: runtime image
FROM python:3.12-slim
WORKDIR /app

# Install necessary runtime packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard \
    iptables \
    iproute2 \
    net-tools \
    inetutils-ping \
    inetutils-traceroute \
    nano \
    openssl \
    dnsutils \
    rrdtool \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from the builder stage
COPY --from=builder /install /usr/local

# Copy the application code
COPY . /app/

# Set execution permissions on scripts
RUN chmod +x /app/init.sh && chmod +x /app/entrypoint.sh

ARG SERVER_ADDRESS
ARG DEBUG_MODE

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/app/init.sh"]
