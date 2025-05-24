#!/usr/bin/env sh
set -eu

PIN_DIR=/sys/fs/bpf/xdp_dsr
VIP=10.10.0.5/32

BK_A=backend-a
BK_B=backend-b
MAX_RETRY=10

# ---------- 1. 找 bridge ----------
BR_IF=$(ip -o -4 addr show | awk '$4=="10.10.0.1/24"{print $2; exit}')
[ -z "$BR_IF" ] && { echo "[lb] bridge 10.10.0.1 not found"; exit 1; }
echo "[lb] Using bridge $BR_IF"

# ---------- 2. 綁 VIP ----------
ip addr replace "$VIP" dev "$BR_IF"
# lb 獲取 mmetrics 使用的 ip
SECOND_IP="10.10.0.6/24"
if ! ip -o -4 addr show dev "$BR_IF" | grep -q "$SECOND_IP"; then
    ip addr add "$SECOND_IP" dev "$BR_IF"
fi

# ---------- 3. 卸舊 XDP + 清 pin ----------
ip link set dev "$BR_IF" xdp off 2>/dev/null || true
rm -rf "$PIN_DIR"
mkdir -p  "$PIN_DIR"

# ---------- 4. 載入程式（僅 load & pin） ----------
bpftool prog load /usr/local/bin/xdp_dsr_kern.o \
                "$PIN_DIR/prog_xdp" type xdp
echo "[lb] program pinned → $PIN_DIR/prog_xdp"

# ---------- 5. 取出並 pin 兩張 map ----------
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

ID_BACKENDS=$(find_map_id backends)  || { echo "[lb] cannot find backends map"; exit 1; }
ID_TXIDX=$(find_map_id tx_ifindex)   || { echo "[lb] cannot find tx_ifindex map"; exit 1; }

bpftool map pin id "$ID_BACKENDS" "$PIN_DIR/backends"
bpftool map pin id "$ID_TXIDX"    "$PIN_DIR/tx_ifindex"
echo "[lb] pin maps → backends=$ID_BACKENDS  tx_ifindex=$ID_TXIDX"

# ---------- 6. 幫手函式 ----------
mac2hex () {                 # 02:42:0a:0a:00:02 → 0x02 0x42 …
  echo "$1" | tr ':' ' ' | awk '{for(i=1;i<=NF;i++) printf "0x%s ",$i}'
}

get_mac_ifidx () {          # $1 = container name
  local pid mac idx retry=0
  pid=$(docker inspect -f '{{.State.Pid}}' "$1") || return 1
  while [ $retry -lt "$MAX_RETRY" ]; do
    mac=$(nsenter -t "$pid" -m -n -- cat /sys/class/net/eth0/address 2>/dev/null || true)
    idx=$(nsenter -t "$pid" -m -n -- cat /sys/class/net/eth0/iflink  2>/dev/null || true)
    [ -n "$mac" ] && [ -n "$idx" ] && { echo "$mac $idx"; return 0; }
    retry=$((retry+1))
    sleep 1
  done
  return 1
}

# ---------- 7. 取得 backend 資訊 ----------
read MAC_A IFIDX_A <<EOF
$(get_mac_ifidx "$BK_A" || { echo "[lb] cannot get info for $BK_A"; exit 1; })
EOF
read MAC_B IFIDX_B <<EOF
$(get_mac_ifidx "$BK_B" || { echo "[lb] cannot get info for $BK_B"; exit 1; })
EOF

echo "[lb] $BK_A mac=$MAC_A ifindex=$IFIDX_A"
echo "[lb] $BK_B mac=$MAC_B ifindex=$IFIDX_B"

# ---------- 8. 寫入 maps ----------
bpftool map update pinned "$PIN_DIR/backends"   key 0 0 0 0 value $(mac2hex "$MAC_A")
bpftool map update pinned "$PIN_DIR/backends"   key 1 0 0 0 value $(mac2hex "$MAC_B")

bpftool map update pinned "$PIN_DIR/tx_ifindex" key 0 0 0 0 value "$IFIDX_A" 0 0 0
bpftool map update pinned "$PIN_DIR/tx_ifindex" key 1 0 0 0 value "$IFIDX_B" 0 0 0
echo "[lb] maps updated"

# ---------- 9. attach 程式到 bridge ----------
ip link set dev "$BR_IF" xdp pinned "$PIN_DIR/prog_xdp"
echo "[lb] XDP attached on $BR_IF"

# echo "[lb] Starting metrics collector in background..."
/usr/local/bin/metrics_collector /usr/local/bin/xdp_dsr_kern.o &

echo "[lb] setup done → sleep"
exec sleep infinity