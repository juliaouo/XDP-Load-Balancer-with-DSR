#!/usr/bin/env sh
set -eu

# lb 獲取 metrics 使用的 ip
SECOND_IP="10.10.0.6/24"
if ! ip -o -4 addr show dev eth0 | grep -q "$SECOND_IP"; then
    ip addr add "$SECOND_IP" dev eth0
fi

# ---------- attach 程式到 bridge ----------
ip link set dev eth0 xdpgeneric obj /usr/local/bin/xdp_lb_kern.o sec xdp_lb
echo "[lb] XDP attached on eth0"

echo "[lb] Starting metrics collector in background..."
/usr/local/bin/metrics_collector /usr/local/bin/xdp_lb_kern.o &

echo "[lb] setup done → sleep"
exec sleep infinity