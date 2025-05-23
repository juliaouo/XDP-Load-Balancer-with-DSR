# ------------------------------------------------------------
#  lb-from-scratch  Makefile（核心必編；loader 有檔才編）
# ------------------------------------------------------------
TARGET  ?= xdp_dsr               # 預設範例
ARCH    ?= x86_64

KERN_SRC  := $(TARGET)_kern.c
BPF_OBJ   := $(TARGET)_kern.o

COLLECTOR_SRC := metrics_collector.c
COLLECTOR_BIN := metrics_collector

LIBBPF_DIR = libbpf/src
CLANG ?= clang
CC    ?= gcc

# ------------ CFLAGS ---------------------------------------------------------
CFLAGS_BPF = -O2 -g -Wall -target bpf \
             -I/usr/include/$(shell uname -m)-linux-gnu \
             -I$(LIBBPF_DIR) -I$(LIBBPF_DIR)/include
CFLAGS_USER = -O2 -g -Wall \
             -I/usr/include/$(shell uname -m)-linux-gnu \
             -I$(LIBBPF_DIR) -I$(LIBBPF_DIR)/include
COLLECTOR_LIBS = -lcurl -ljson-c
# ------------ Rules ----------------------------------------------------------
all: $(BPF_OBJ) $(COLLECTOR_BIN)

$(BPF_OBJ): $(KERN_SRC)
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

$(COLLECTOR_BIN): $(COLLECTOR_SRC) $(LIBBPF_DIR)/libbpf.a
	$(CC) $(CFLAGS_USER) $< $(LIBBPF_DIR)/libbpf.a -lelf -lz $(COLLECTOR_LIBS) -o $@

$(LIBBPF_DIR)/libbpf.a:
	$(MAKE) -C $(LIBBPF_DIR)

clean:
	rm -f *.o $(COLLECTOR_BIN) $(USER_BIN)
	rm -f *.ll
.PHONY: all clean

