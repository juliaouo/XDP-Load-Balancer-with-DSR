#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u8  proto;
    __u16 src_port;
    __u16 dst_port;
} __attribute__((packed));

// 後端伺服器狀態結構
struct backend_stats {
    __u32 cpu_percent;     // CPU 使用率 (0-10000, 表示 0.00% - 100.00%)
    __u32 avg_latency;     // 平均延遲 (ms * 100, 保留兩位小數)
    __u64 last_updated;    // 最後更新時間 (ns)
    __u32 active_conns;    // 活躍連線數
};
