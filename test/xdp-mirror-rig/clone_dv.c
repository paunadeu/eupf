#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

#ifndef BPF_F_BROADCAST
#define BPF_F_BROADCAST (1ULL << 3)
#endif
#ifndef BPF_F_EXCLUDE_INGRESS
#define BPF_F_EXCLUDE_INGRESS (1ULL << 4)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_devmap_val));
    __uint(max_entries, 2);
} mirror SEC(".maps");

/* Broadcast-clone the ingress frame to every device in the mirror devmap. Pass
 * anything that is not IPv4 (ARP, IPv6 ND) to the stack so neighbour resolution
 * still works and the generator can reach this device. */
SEC("xdp")
int clone_bcast(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    return bpf_redirect_map(&mirror, 0, BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
}

/* A no-op attached to the injection peer so veth brings up its native XDP RX
 * path; veth needs an XDP program on both ends for native mode. Its own section
 * so `ip link ... sec` can select it. */
SEC("xdp/pass")
int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}
