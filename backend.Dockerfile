# backend.Dockerfile  ── 用於 DSR（VIP 綁定在 lo，不在此處設定 sysctl）

FROM python:3.12-slim

# 1. 安裝 iproute2（用於 ip addr），並清理 apt 快取
RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 && \
    rm -rf /var/lib/apt/lists/*

# 2. 複製應用程式並安裝 Python 依賴：Flask、psutil、Gunicorn
WORKDIR /app
COPY server.py /app/
RUN pip install --no-cache-dir flask psutil gunicorn

# 3. 產生啟動腳本：先綁定 VIP，再啟動多 worker 的 Gunicorn
RUN cat > /usr/local/bin/start-backend <<EOF
#!/bin/sh
set -e    # 遇到錯誤就退出

# 啟動 Gunicorn
exec gunicorn server:app \
    --workers  8\
    --bind 0.0.0.0:80 \
    --worker-class sync \
    --backlog 4096
EOF

# 4. 賦予啟動腳本執行權限
RUN chmod +x /usr/local/bin/start-backend

# 5. 容器啟動時執行 start-backend
ENTRYPOINT ["/usr/local/bin/start-backend"]
