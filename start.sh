#!/usr/bin/env sh
set -eu

# lb 獲取 metrics 使用的 ip
SECOND_IP="10.10.0.6/24"
if ! ip -o -4 addr show dev eth0 | grep -q "$SECOND_IP"; then
    ip addr add "$SECOND_IP" dev eth0
fi

PIN_DIR=/sys/fs/bpf/xdp_dsr

# ---------- 卸舊 XDP + 清 pin ----------
ip link set dev eth0 xdp off 2>/dev/null || true
rm -rf "$PIN_DIR"
mkdir -p  "$PIN_DIR"

# ---------- 載入程式（僅 load & pin） ----------
bpftool prog load /usr/local/bin/xdp_lb_kern.o \
                "$PIN_DIR/prog_xdp" type xdp
echo "[lb] program pinned → $PIN_DIR/prog_xdp"

find_map_id() {               # $1 = backends | tx_ifindex
  local want="$1" id mname

  # 1) 先把 map_ids 取乾淨 → "269 266 267 268 271"
  for id in $(bpftool prog show pin "$PIN_DIR/prog_xdp" \
                 | sed -n 's/.*map_ids \([0-9,]*\).*/\1/p' \
                 | tr ',' ' '); do

    # 2) 真正讀 map 的名稱；第一行一定含有 "name XXX"
    mname=$(bpftool map show id "$id" | awk '/[[:space:]]name[[:space:]]/{print $4; exit}')
    if [ "$mname" = "$want" ]; then
        echo "$id"; return 0
    fi
  done
  return 1                # 全掃完還沒命中
}

ID_STATS=$(find_map_id backend_stats_m) || { echo "[lb] cannot find backend_stats_m map"; exit 1; }
bpftool map pin id "$ID_STATS"    "$PIN_DIR/backend_stats_m"

# ---------- attach 程式到 bridge ----------
ip link set dev eth0 xdpgeneric pinned "$PIN_DIR/prog_xdp"
echo "[lb] XDP attached on eth0"

echo "[lb] Starting metrics collector in background..."
/usr/local/bin/metrics_collector /usr/local/bin/xdp_lb_kern.o &

echo "[lb] setup done → sleep"
exec sleep infinity