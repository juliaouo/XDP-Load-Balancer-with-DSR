# backend.Dockerfile  ── for DSR (VIP on lo, no sysctl here)

FROM python:3.12-slim

# 1. 裝 iproute2，才能用 `ip addr`
RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 && \
    rm -rf /var/lib/apt/lists/*

# 2. 安裝 app
WORKDIR /app
COPY server.py /app/
RUN pip install --no-cache-dir flask psutil

# 3. 啟動腳本：綁 VIP → 進 Flask
RUN printf '%s\n' \
  '#!/bin/sh' \
  'set -e' \
  'ip addr add 10.10.0.5/32 dev lo' \
  'exec python /app/server.py' \
  > /usr/local/bin/start-backend && chmod +x /usr/local/bin/start-backend

ENTRYPOINT ["/usr/local/bin/start-backend"]

