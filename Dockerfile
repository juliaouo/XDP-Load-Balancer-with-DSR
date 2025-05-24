#####################################################################
# Stage 1 – build
#####################################################################
FROM ubuntu:jammy AS build
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang llvm build-essential make git \
    libelf-dev zlib1g-dev pkg-config linux-headers-generic \
    libcurl4-openssl-dev libjson-c-dev \
    linux-libc-dev

WORKDIR /src
COPY . /src

# 靜態 bpftool
RUN git clone --depth 1 --recurse-submodules \
      https://github.com/libbpf/bpftool.git /tmp/bpftool && \
    make -C /tmp/bpftool/src EXTRA_CFLAGS='-static' bpftool && \
    strip /tmp/bpftool/src/bpftool && \
    install -m 0755 /tmp/bpftool/src/bpftool /usr/local/bin/

# 編譯 libbpf + XDP 範例
ARG TARGET=xdp_dsr
RUN make -C libbpf/src && \
    make TARGET=${TARGET}

RUN ls -la /src/*.o /src/metrics_collector* || echo "Build artifacts check"

#####################################################################
# Stage 2 – runtime
#####################################################################
FROM ubuntu:jammy
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /work

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev linux-tools-common iproute2 ethtool \
    libcurl4 libjson-c5 python3 python3-pip \
    curl iputils-ping net-tools tcpdump kmod

# 拷貝編譯產物
COPY --from=build /usr/local/bin/bpftool /usr/local/bin/
COPY --from=build /src/xdp_dsr_kern.o /usr/local/bin/
COPY --from=build /src/metrics_collector /usr/local/bin/

# 拷貝 Python 後端伺服器
COPY server.py /usr/local/bin/

# 去掉 Ubuntu 自帶的 wrapper，使用我們編譯的 bpftool
RUN rm -f /usr/sbin/bpftool /usr/bin/bpftool && \
    ln -s /usr/local/bin/bpftool /usr/sbin/bpftool && \
    ln -s /usr/local/bin/bpftool /usr/bin/bpftool

RUN cat > /usr/local/bin/lb-status.sh <<'EOF'
#!/bin/bash
IFACE=${IFACE:-eth0}

echo "=== Smart Load Balancer Status ==="
echo ""

echo "Network Interface Status:"
ip link show $IFACE | grep xdp || echo "No XDP program loaded on $IFACE"

echo ""
echo "BPF Maps:"
echo "Backend Stats:"
bpftool map dump name backend_stats_m 2>/dev/null || echo "backend_stats_m not found"

echo ""
echo "Connection Map:"
bpftool map dump name connection_map 2>/dev/null || echo "connection_map not found"
EOF

# 讓腳本可執行
RUN chmod +x /usr/local/bin/*.sh

RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io util-linux 

# 設定環境變數
ENV PATH="/usr/local/bin:${PATH}"
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh
ENTRYPOINT ["/usr/local/bin/start.sh"]
