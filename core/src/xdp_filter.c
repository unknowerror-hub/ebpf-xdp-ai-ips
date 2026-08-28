#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

BPF_HASH(whitelist_map, u32, u8); 
BPF_HASH(blacklist_map, u32, u8); 
BPF_PERF_OUTPUT(events);          

struct pkt_meta {
    u32 src_ip;
    u32 dst_ip;
    u16 sport;
    u16 dport;
};

int xdp_fw_router(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    u32 src_ip = iph->saddr;

    u8 *white = whitelist_map.lookup(&src_ip);
    if (white) return XDP_PASS;

    u8 *black = blacklist_map.lookup(&src_ip);
    if (black) return XDP_DROP;

    struct pkt_meta meta = {};
    meta.src_ip = src_ip;
    meta.dst_ip = iph->daddr;

    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        u16 *ports = (void *)(iph + 1);
        if ((void *)(ports + 2) <= data_end) {
            meta.sport = __constant_ntohs(ports);
            meta.dport = __constant_ntohs(ports);
        }
    }

    events.perf_submit(ctx, &meta, sizeof(meta));
    return XDP_PASS;
}
