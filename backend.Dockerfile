# backend.Dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY server.py /app/
RUN pip install --no-cache-dir flask
# 小腳本：先 bind VIP，再啟動 Flask
RUN printf '%s\n' \
  '#!/bin/sh' \
  'ip addr add 10.10.0.5/32 dev lo' \
  'exec python /app/server.py' > /usr/local/bin/start-backend && \
  chmod +x /usr/local/bin/start-backend
ENTRYPOINT ["/usr/local/bin/start-backend"]

