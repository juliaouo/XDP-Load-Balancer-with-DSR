#!/usr/bin/env bash
set -e

PIN_DIR=/sys/fs/bpf/xdp_dsr
BK_IP_A=10.10.0.2   # backend-a IP
BK_IP_B=10.10.0.3   # backend-b IP

# ---------- 1. 橋 ----------
BR_IF=$(ip -o addr show | awk '/10\.10\.0\.1\/24/ {print $2}' | head -n1)
[ -z "$BR_IF" ] && echo "[lb] bridge not found" && exit 1
echo "[lb] Using bridge $BR_IF"

# ---------- 2. VIP ----------
ip addr add 10.10.0.5/32 dev "$BR_IF" 2>/dev/null || true

# ---------- 3. 卸舊 XDP + 清 pin ----------
ip link set dev "$BR_IF" xdp off
rm -rf "$PIN_DIR" && mkdir -p "$PIN_DIR"

# ---------- 4. 載入程式 ----------
bpftool -f prog load /usr/local/bin/xdp_dsr_kern.o \
        "$PIN_DIR/prog_xdp" type xdp
echo "[lb] program pinned → $PIN_DIR/prog_xdp"

# ---------- 5. PIN maps ----------
MAP_IDS=$(bpftool prog show pin "$PIN_DIR/prog_xdp" |
          awk '/map_ids/ {gsub(/,/, " "); for(i=2;i<=NF;i++) if($i~/^[0-9]+$/) print $i}')
set -- $MAP_IDS    # $1 backends, $2 tx_ifindex
bpftool -f map pin id "$1" "$PIN_DIR/backends"
bpftool -f map pin id "$2" "$PIN_DIR/tx_ifindex"

# ---------- 6. 動態抓 MAC + ifindex ----------
get_mac_ifidx () {               # $1 = container name
  local pid
  pid=$(docker inspect -f '{{.State.Pid}}' "$1") || {
        echo "[lb] cannot get pid for $1"; exit 1; }

  local mac ifidx_host
  # 同時切換 mount (-m) 與 network (-n) namespace 才能看到 container 自己的 /sys
  mac=$(nsenter -t "$pid" -m -n -- cat /sys/class/net/eth0/address)
  # eth0 的 iflink = host veth ifindex
  ifidx_host=$(nsenter -t "$pid" -m -n -- cat /sys/class/net/eth0/iflink)

  echo "$mac $ifidx_host"
}

read MAC_A IFIDX_A <<<"$(get_mac_ifidx backend-a)"
read MAC_B IFIDX_B <<<"$(get_mac_ifidx backend-b)"

echo "[lb] backend-A mac=$MAC_A  ifindex=$IFIDX_A"
echo "[lb] backend-B mac=$MAC_B  ifindex=$IFIDX_B"

mac2hex () {               # 02:42:0a:0a:00:02 → 0x02 0x42 …
  echo $1 | tr ':' ' ' | awk '{for(i=1;i<=NF;i++) printf "0x%s ",$i}'
}

# ---------- 7. 寫入 map（依你要求的語法） ----------
bpftool map update pinned $PIN_DIR/backends   key 0 0 0 0 value $(mac2hex $MAC_A)
bpftool map update pinned $PIN_DIR/backends   key 1 0 0 0 value $(mac2hex $MAC_B)

bpftool map update pinned $PIN_DIR/tx_ifindex key 0 0 0 0 value $IFIDX_A 0 0 0
bpftool map update pinned $PIN_DIR/tx_ifindex key 1 0 0 0 value $IFIDX_B 0 0 0

echo "[lb] maps updated → sleep"
exec sleep infinity
