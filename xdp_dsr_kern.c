#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf_endian.h>

#define VIP_IP    bpf_htonl(0x0A0A0005)  /* 10.10.0.5 */
#define MAX_BE    2

struct backend {
    __u8 mac[6];
};

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

    /* 轮询选 backend（0 或 1）*/
    key = bpf_ktime_get_ns() & (MAX_BE - 1);

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
