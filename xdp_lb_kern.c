#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf_endian.h>
#include "xdp_lb_kern.h"
#include <linux/tcp.h>

#define IP_ADDRESS(x) (unsigned int)(10 + (10 << 8) + (0 << 16) + ((x) << 24))

#define BACKEND_A 2
#define BACKEND_B 3
#define LB 5

#define VIP_IP    bpf_htonl(0x0A0A0005)  // 10.10.0.5
#define MAX_BE    2

struct backend {
    __u8 mac[6];
};

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
            return (bpf_ktime_get_ns() % 2) ? BACKEND_A : BACKEND_B;
        }
        // 只有 B 有資料
        return BACKEND_B;
    }
    struct backend_stats *stats_b = bpf_map_lookup_elem(&backend_stats_m, &backend_b_ip);
    if (!stats_b) {
        // 只有 A 有資料
        return BACKEND_A;
    }

    // 算負載分數並選擇較低的
    __u32 score_a = calculate_load_score(stats_a);
    __u32 score_b = calculate_load_score(stats_b);
    
    bpf_printk("Backend A score: %u, Backend B score: %u", score_a, score_b);
    
    return (score_a <= score_b) ? BACKEND_A : BACKEND_B;
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

SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
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

    // TCP 還要 parse port，必須先確認 L4 header 在 bounds 內
    struct tcphdr *th = (void*)iph + sizeof(*iph);
    if ((void*)(th + 1) > data_end) {
        // TCP 頭不完整，就不做 DS-Rewrite，直接交給內核
        return XDP_PASS;
    }

    struct flow_key fk = {
        .src_ip   = iph->saddr,
        .dst_ip   = iph->daddr,
        .proto    = iph->protocol,
        .src_port = bpf_ntohs(th->source),
        .dst_port = bpf_ntohs(th->dest),
    };

    if (iph->saddr != IP_ADDRESS(BACKEND_A) && iph->saddr != IP_ADDRESS(BACKEND_B)) {
        __u32 selected_backend;
        __u32 backend_ip;
        __u32 *p = bpf_map_lookup_elem(&connection_map, &fk);
        if (p) {
            selected_backend = *p;
            backend_ip = IP_ADDRESS(selected_backend);
        } else {
            // 選擇後端
            selected_backend = select_best_backend();
            // 更新去程 key
            bpf_map_update_elem(&connection_map, &fk, &selected_backend, BPF_ANY);
            backend_ip = IP_ADDRESS(selected_backend);
            update_connection_count(backend_ip, 1);

            // 更新返程 key
            struct flow_key fk_rev = {
                .src_ip   = IP_ADDRESS(selected_backend),
                .dst_ip   = fk.dst_ip,
                .proto    = fk.proto,
                .src_port = fk.dst_port,
                .dst_port = fk.src_port,
            };
            __u32 client_idx = bpf_ntohl(fk.src_ip) & 0xFF;
            bpf_map_update_elem(&connection_map, &fk_rev, &client_idx, BPF_ANY);
        }

        iph->daddr = backend_ip;
        eth->h_dest[5] = selected_backend;
    }
    else
    {
        __u32 *p = bpf_map_lookup_elem(&connection_map, &fk);
        if (p) {
            __u32 client_idx = *p;
            __u32 client_ip = IP_ADDRESS(client_idx);
            iph->daddr = client_ip;
            eth->h_dest[5] = client_idx;
        }
        // 如果沒命中，只 PASS 回內核
        else {
            bpf_printk("XDP: reply not match\n");
            return XDP_PASS;
        }
    }
    iph->saddr = IP_ADDRESS(LB);
    eth->h_source[5] = LB;

    iph->check = iph_csum(iph);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";