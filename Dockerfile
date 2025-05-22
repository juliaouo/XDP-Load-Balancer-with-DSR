#####################################################################
# Stage 1 – build
#####################################################################
FROM ubuntu:jammy AS build
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang llvm build-essential make git \
    libelf-dev zlib1g-dev pkg-config linux-headers-generic

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

#####################################################################
# Stage 2 – runtime
#####################################################################
FROM ubuntu:jammy
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /work

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev linux-tools-common iproute2 ethtool

# 拷貝 bpftool 與 *_kern.o（至少會有一個）
COPY --from=build /usr/local/bin/bpftool /usr/local/bin/
COPY --from=build /src/*_kern.o              /usr/local/bin/

# → 若你確定某個檔案未來 *一定* 會存在，再額外加 COPY 行；
#   否則請保持最小集合，避免「無檔案 → build fail」。

# 去掉 Ubuntu 自帶的 wrapper
RUN rm -f /usr/sbin/bpftool && \
    ln -s /usr/local/bin/bpftool /usr/sbin/bpftool

RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io util-linux 

ENV PATH="/usr/local/bin:${PATH}"
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh
ENTRYPOINT ["/usr/local/bin/start.sh"]

