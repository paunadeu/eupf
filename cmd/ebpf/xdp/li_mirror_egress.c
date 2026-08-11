/**
 * Copyright 2025 Edgecom LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef BPF_FIB_LOOKUP_OUTPUT
#define BPF_FIB_LOOKUP_OUTPUT (1U << 1)
#endif

/* Where a mirror device sends the intercepted copy. Slot 0 holds the downlink
 * collector; it is populated from configuration at startup. An unset or zero
 * collector makes the program ship the clone unchanged rather than misdeliver
 * it. */
struct mirror_cfg {
    __u32 collector_ip; /* outer IPv4 destination to rewrite to (network order) */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct mirror_cfg);
    __uint(max_entries, 1);
} mirror_cfg_dl SEC(".maps");

/* Recompute the IPv4 header checksum over a fixed 20-octet header (no options).
 * The caller has already bounds-checked that the full header is in the packet. */
static __always_inline __u16 ipv4_header_csum(struct iphdr *ip) {
    ip->check = 0;
    __u16 *w = (__u16 *)ip;
    __u32 sum = 0;
#pragma unroll
    for (int i = 0; i < 10; i++)
        sum += w[i];
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16)~sum;
}

/* Devmap egress program for the downlink interception copy. It runs only on the
 * cloned frame handed to the mirror device by the main program's broadcast
 * redirect, so its header edits never touch the real-egress copy. The clone is
 * already a GTP-U PDU carrying the bearer TEID, which is the settled collector
 * wire format, so this leg only re-points the outer destination at the
 * collector, fixes the IPv4 checksum, resolves the L2 nexthop, and lets the
 * device transmit (XDP_PASS). A devmap egress program cannot redirect again.
 * The uplink leg re-encapsulates a decapsulated inner packet and needs the
 * per-session TEID; it is a separate program and is not built here. */
SEC("xdp/devmap")
int li_mirror_dl(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;
    if (ip->ihl != 5) /* outer header has no options; leave anything else alone */
        return XDP_PASS;

    __u32 key = 0;
    struct mirror_cfg *cfg = bpf_map_lookup_elem(&mirror_cfg_dl, &key);
    if (!cfg || !cfg->collector_ip)
        return XDP_PASS;

    ip->daddr = cfg->collector_ip;
    ip->check = ipv4_header_csum(ip);

    /* GTP-U rides UDP, and the outer UDP checksum covers a pseudo-header that
     * includes the destination address, so rewriting daddr invalidates it.
     * Disable it: a zero checksum is legal for IPv4 UDP and is exactly what the
     * fork's own GTP-U encapsulation emits, so the collector accepts the copy. */
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)(udp + 1) <= data_end)
            udp->check = 0;
    }

    struct bpf_fib_lookup fib = {};
    fib.family = AF_INET;
    fib.l4_protocol = ip->protocol;
    fib.tot_len = bpf_ntohs(ip->tot_len);
    fib.ipv4_src = ip->saddr;
    fib.ipv4_dst = ip->daddr;
    /* Constrain the route to the mirror device and treat the copy as locally
     * originated (OUTPUT), so the lookup does not depend on ip_forward and only
     * succeeds if the collector is actually reachable out of this device. */
    fib.ifindex = ctx->egress_ifindex;

    /* A devmap egress program transmits on XDP_PASS with no stack fallback and
     * no neighbour resolution, so a frame with an unresolved nexthop would leave
     * the mirror device misaddressed. Drop the copy on any lookup failure rather
     * than blackhole or misdeliver the intercept. */
    if (bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_OUTPUT) != BPF_FIB_LKUP_RET_SUCCESS)
        return XDP_DROP;
    /* The resolved route must leave by the mirror device itself; a route out of
     * another interface would stamp MACs valid only on that other segment. */
    if (fib.ifindex != ctx->egress_ifindex)
        return XDP_DROP;
    __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
