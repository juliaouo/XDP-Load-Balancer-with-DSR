#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf_endian.h>
#include "xdp_dsr_kern.h"
#include <linux/tcp.h>
#define TCP_SYN 0x02
#define TCP_ACK 0x10

#define IP_ADDRESS(x) (unsigned int)(10 + (10 << 8) + (0 << 16) + (x << 24))

#define BACKEND_A 2
#define BACKEND_B 3

#define VIP_IP    bpf_htonl(0x0A0A0005)  /* 10.10.0.5 */
#define MAX_BE    2

struct backend {
    __u8 mac[6];
};

// static const __u32 backend_ips[MAX_BE] = {
//     [0] = IP_ADDRESS(BACKEND_A),
//     [1] = IP_ADDRESS(BACKEND_B),
// };

/* 后端 MAC 列表 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BE);
    __type(key,   __u32);
    __type(value, struct backend);
} backends SEC(".maps");

/* 后端容器 veth ifindex 列表 */
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
    __uint(max_entries, 16);
} backend_stats_m SEC(".maps");

// BPF Map: 儲存連線追蹤 (5-tuple)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct flow_key);
    __type(value, __u32);   // backend index
} connection_map SEC(".maps");

// 計算後端伺服器的負載分數 (越低越好)
static __always_inline __u32 calculate_load_score(struct backend_stats *stats) {
    __u64 now = bpf_ktime_get_ns();
    
    // 如果統計資料太舊 (超過 10 秒)，給予懲罰分數
    if (now - stats->last_updated > 10000000000ULL) {
        return 999999; // 高懲罰分數
    }
    
    // 負載分數 = CPU使用率 * 100 + 平均延遲 + 活躍連線數 * 10
    // 這個公式可以根據需求調整權重
    __u32 score = (stats->cpu_percent / 100) * 100 +  // CPU 權重
                  (stats->avg_latency / 100) +         // 延遲權重
                  stats->active_conns * 10;            // 連線數權重
    
    return score;
}

// 選擇最佳後端伺服器
static __always_inline __u32 select_best_backend(void) {
    __u32 backend_a_ip = IP_ADDRESS(BACKEND_A);
    __u32 backend_b_ip = IP_ADDRESS(BACKEND_B);

    struct backend_stats *stats_a = bpf_map_lookup_elem(&backend_stats_m, &backend_a_ip);
    if (!stats_a) {
        struct backend_stats *stats_b = bpf_map_lookup_elem(&backend_stats_m, &backend_b_ip);
        if (!stats_b) {
            // 兩邊都沒資料，fallback to round-robin
            return (bpf_ktime_get_ns() % 2) ? 0 : 1;
        }
        // 只有 B 有資料
        return 1;
    }
    struct backend_stats *stats_b = bpf_map_lookup_elem(&backend_stats_m, &backend_b_ip);
    if (!stats_b) {
        // 只有 A 有資料
        return 0;
    }

    // 算負載分數並選擇較低的
    __u32 score_a = calculate_load_score(stats_a);
    __u32 score_b = calculate_load_score(stats_b);
    
    bpf_printk("Backend A score: %u, Backend B score: %u", score_a, score_b);
    
    return (score_a <= score_b) ? 0 : 1;
}

// 更新連線計數
static __always_inline void update_connection_count(__u32 backend_ip, int delta) {
    struct backend_stats *stats = bpf_map_lookup_elem(&backend_stats_m, &backend_ip);
    if (stats) {
        if (delta > 0) {
            stats->active_conns++;
        } else if (delta < 0 && stats->active_conns > 0) {
            stats->active_conns--;
        }
        bpf_map_update_elem(&backend_stats_m, &backend_ip, stats, BPF_ANY);
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

    /* L2 边界检查 */
    if ((void*)(eth + 1) > data_end) {
        bpf_printk("XDP: drop ethhdr OOB\n");
        return XDP_ABORTED;
    }

    /* 只处理 IPv4 */
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        bpf_printk("XDP: non-IP, PASS\n");
        return XDP_PASS;
    }

    iph = (void*)(eth + 1);
    /* L3 边界检查 */
    if ((void*)(iph + 1) > data_end) {
        bpf_printk("XDP: drop iphdr OOB\n");
        return XDP_ABORTED;
    }

    /* 只处理 VIP */
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

    __u8 *tcp_hdr = (void*)th;
    __u8 flags = tcp_hdr[13];

    __u32 selected_backend;
    __u32 *p = bpf_map_lookup_elem(&connection_map, &fk);
    if (p) {
        selected_backend = *p;
    } else if ((flags & TCP_SYN) && !(flags & TCP_ACK)) {
        selected_backend = select_best_backend();
        bpf_map_update_elem(&connection_map, &fk, &selected_backend, BPF_ANY);
        // __u32 backend_ip = backend_ips[selected_backend];
        __u32 backend_ip = IP_ADDRESS(selected_backend + 2);
        update_connection_count(backend_ip, 1);
    } else {
        return XDP_PASS;
    }

    key = selected_backend;

    /* 查 MAC 并改写 */
    struct backend *be = bpf_map_lookup_elem(&backends, &key);
    if (!be) {
        bpf_printk("XDP: map miss backends key=%u\n", key);
        return XDP_PASS;
    }
    __builtin_memcpy(eth->h_dest, be->mac, 6);
    bpf_printk("XDP: rewrote dst MAC key=%u\n", key);

    /* 查 ifindex 并重定向 */
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
