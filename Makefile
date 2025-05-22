# ------------------------------------------------------------
#  lb-from-scratch  Makefile（核心必編；loader 有檔才編）
# ------------------------------------------------------------
TARGET  ?= xdp_dsr               # 預設範例
ARCH    ?= x86_64

KERN_SRC  := $(TARGET)_kern.c
BPF_OBJ   := $(TARGET)_kern.o

# 嘗試找 <target>_user.c；有檔才編
ifneq ("$(wildcard $(TARGET)_user.c)","")
  USER_SRC := $(TARGET)_user.c
  USER_BIN := $(TARGET)_user
endif

LIBBPF_DIR = libbpf/src
CLANG ?= clang
CC    ?= gcc

# ------------ CFLAGS ---------------------------------------------------------
CFLAGS_BPF = -O2 -g -Wall -target bpf \
             -I/usr/include/$(shell uname -m)-linux-gnu \
             -I$(LIBBPF_DIR) -I$(LIBBPF_DIR)/include
CFLAGS_USER = -O2 -g -Wall -static

# ------------ Rules ----------------------------------------------------------
all: $(BPF_OBJ) $(USER_BIN)

$(BPF_OBJ): $(KERN_SRC)
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

# 只有當 USER_SRC / USER_BIN 都非空時才生成 loader 目標
ifneq ($(USER_BIN),)
$(USER_BIN): $(USER_SRC) $(LIBBPF_DIR)/libbpf.a
	$(CC) $(CFLAGS_USER) $< $(LIBBPF_DIR)/libbpf.a -lelf -lz -o $@
endif

$(LIBBPF_DIR)/libbpf.a:
	$(MAKE) -C $(LIBBPF_DIR)

clean:
	rm -f *.o *_user
.PHONY: all clean

