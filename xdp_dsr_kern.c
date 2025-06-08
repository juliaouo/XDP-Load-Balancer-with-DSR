#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf_endian.h>
#include "xdp_dsr_kern.h"
#include <linux/tcp.h>

#define IP_ADDRESS(x) (unsigned int)(10 + (10 << 8) + (0 << 16) + ((x) << 24))

#define BACKEND_A 2
#define BACKEND_B 3

#define VIP_IP    bpf_htonl(0x0A0A0005)  // 10.10.0.5
#define MAX_BE    16

struct backend {
    __u8 mac[6];
};

// 後端 MAC 列表
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BE);
    __type(key,   __u32);
    __type(value, struct backend);
} backends SEC(".maps");

// 後端容器 veth ifindex 列表
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BE);
    __type(key,   __u32);
    __type(value, __u32);
} tx_ifindex SEC(".maps");

// BPF Map: 儲存後端伺服器統計資料
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct backend_stats);
    __uint(max_entries, MAX_BE);
} backend_stats_m SEC(".maps");

// BPF Map: 儲存連線追蹤 (5-tuple)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct flow_key);
    __type(value, __u32);   // backend index
} connection_map SEC(".maps");

/* 全局 policy 設定：key=0, value=policy_id */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} policy_cfg SEC(".maps");

/* key = 0，value = 權重結構；由 user space 動態調整 */
struct weight_cfg {
    __u32 w_cpu;     
    __u32 w_lat;    
    __u32 w_conn;    
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct weight_cfg);
} weight_map SEC(".maps");

static __always_inline __u32
calculate_load_score(const struct backend_stats *stats)
{
    /* 1️⃣ 檢查資料新舊 */
    if (bpf_ktime_get_ns() - stats->last_updated > 10ULL * 1e9)
        return 999999;       /* 過期直接懲罰 */

    /* 2️⃣ 讀取權重（若查不到，用內建預設） */
    __u32 zero = 0;
    const struct weight_cfg *w = bpf_map_lookup_elem(&weight_map, &zero);
    __u32 wc = w ? w->w_cpu  : 100;
    __u32 wl = w ? w->w_lat  :   1;
    __u32 wa = w ? w->w_conn :  10;

    /* 3️⃣ 計分 (越低越好) */
    return (stats->cpu_percent / 100) * wc +
           (stats->avg_latency / 100) * wl +
           stats->active_conns * wa;
}

// 選擇最佳後端伺服器
static __always_inline __u32
select_best_backend(void)
{
    __u32 backend_a_ip = IP_ADDRESS(BACKEND_A);
    __u32 backend_b_ip = IP_ADDRESS(BACKEND_B);

    /* 1️⃣  讀當前 policy（查不到就用 0） */
    __u32 zero = 0, policy = 0;
    __u32 *p_pol = bpf_map_lookup_elem(&policy_cfg, &zero);
    if (p_pol)
        policy = *p_pol;

    struct backend_stats *stats_a = bpf_map_lookup_elem(&backend_stats_m, &backend_a_ip);
    struct backend_stats *stats_b = bpf_map_lookup_elem(&backend_stats_m, &backend_b_ip);
    if (!stats_a) {
        if (!stats_b) {
            // 兩邊都沒資料，fallback to round-robin
            return (bpf_ktime_get_ns() % 2) ? BACKEND_A : BACKEND_B;
        }
        // 只有 B 有資料
        return BACKEND_B;
    }
    if (!stats_b) {
        // 只有 A 有資料
        return BACKEND_A;
    }

    /* 計分 */
    __u32 score_a = calculate_load_score(stats_a);
    __u32 score_b = calculate_load_score(stats_b);

    /* 2️⃣  根據 policy 決策 */
    switch (policy) {
    case 1: { /* Policy 1 : random 50/50 */
        bpf_printk("XDP: policy random\n");
        return (bpf_get_prandom_u32() & 1) ? BACKEND_A : BACKEND_B;
    }

    case 2: { /* Policy 2 : Weighted-random (1/score) */
        /* 避免除以 0：若 score==0 視為最低 1 */
        __u64 inv_a = score_a ? (1000000ULL / score_a) : 1000000ULL;
        __u64 inv_b = score_b ? (1000000ULL / score_b) : 1000000ULL;
        __u64 total = inv_a + inv_b;
        /* 產生 0..total-1 的隨機值 */
        __u64 r = bpf_get_prandom_u32();
        r = (r * total) >> 32;
        bpf_printk("XDP: policy Weighted-random\n");
        return (r < inv_a) ? BACKEND_A : BACKEND_B;
    }

    case 0:  /* fall-through */
    default: /* Policy 0 : 選分數最小 */
        bpf_printk("XDP: policy default\n");
        return (score_a <= score_b) ? BACKEND_A : BACKEND_B;
    }
}

// 更新連線計數
static __always_inline void update_connection_count(__u32 backend_ip, int delta) {
    struct backend_stats *stats = bpf_map_lookup_elem(&backend_stats_m, &backend_ip);
    if (stats) {
        struct backend_stats new_stats = *stats;
        if (delta > 0) {
            new_stats.active_conns++;
        } else if (delta < 0 && new_stats.active_conns > 0) {
            new_stats.active_conns--;
        }
        bpf_map_update_elem(&backend_stats_m, &backend_ip, &new_stats, BPF_ANY);
    }
}

SEC("xdp_dsr")
int xdp_dsr_lb(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr  *iph;
    __u32 key, ifidx;

    bpf_printk("XDP: start\n");

    // L2 邊界檢查
    if ((void*)(eth + 1) > data_end) {
        bpf_printk("XDP: drop ethhdr OOB\n");
        return XDP_ABORTED;
    }

    // 只處理 IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        bpf_printk("XDP: non-IP, PASS\n");
        return XDP_PASS;
    }

    iph = (void*)(eth + 1);
    // L3 邊界檢查
    if ((void*)(iph + 1) > data_end) {
        bpf_printk("XDP: drop iphdr OOB\n");
        return XDP_ABORTED;
    }

    // 只處理 VIP
    if (iph->daddr != VIP_IP) {
        bpf_printk("XDP: not VIP 0x%x, PASS\n", bpf_ntohl(iph->daddr));
        return XDP_PASS;
    }
    bpf_printk("XDP: matched VIP\n");

    struct flow_key fk = {
        .src_ip   = iph->saddr,
        .dst_ip   = iph->daddr,
        .proto    = iph->protocol,
    };
    // TCP 還要 parse port，必須先確認 L4 header 在 bounds 內
    struct tcphdr *th = (void*)iph + sizeof(*iph);
    if ((void*)(th + 1) > data_end) {
        // TCP 頭不完整，就不做 DS-Rewrite，直接交給內核
        return XDP_PASS;
    }
    fk.src_port = bpf_ntohs(th->source);
    fk.dst_port = bpf_ntohs(th->dest);

    __u32 selected_backend;
    __u32 *p = bpf_map_lookup_elem(&connection_map, &fk);
    if (p) {
        selected_backend = *p;

        // 檢查是否為 TCP FIN 或 RST 封包
        if (iph->protocol == IPPROTO_TCP) {
            if (th->fin || th->rst) {
                // 取得 backend_ip
                __u32 backend_ip = IP_ADDRESS(selected_backend);
                // 從 connection_map 移除
                bpf_map_delete_elem(&connection_map, &fk);
                // 遞減 active_conns
                update_connection_count(backend_ip, -1);
            }
        }
    } else {
        selected_backend = select_best_backend();
        bpf_map_update_elem(&connection_map, &fk, &selected_backend, BPF_ANY);
        // __u32 backend_ip = backend_ips[selected_backend];
        __u32 backend_ip = IP_ADDRESS(selected_backend);
        update_connection_count(backend_ip, 1);
    }

    key = selected_backend;

    // 查 MAC 並改寫
    struct backend *be = bpf_map_lookup_elem(&backends, &key);
    if (!be) {
        bpf_printk("XDP: map miss backends key=%u\n", key);
        return XDP_PASS;
    }
    __builtin_memcpy(eth->h_dest, be->mac, 6);
    bpf_printk("XDP: rewrote dst MAC key=%u\n", key);

    // 查 ifindex 並重定向
    __u32 *p_if = bpf_map_lookup_elem(&tx_ifindex, &key);
    if (!p_if) {
        bpf_printk("XDP: map miss tx_ifindex key=%u\n", key);
        return XDP_PASS;
    }
    ifidx = *p_if;
    bpf_printk("XDP: redirect to ifindex=%u\n", ifidx);
    return bpf_redirect(ifidx, 0);
}

char _license[] SEC("license") = "GPL";
