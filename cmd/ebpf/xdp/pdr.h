/**
 * Copyright 2023-2025 Edgecom LLC
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

#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/ipv6.h>

#include "xdp/sdf_filter.h"
#include "xdp/sizing.h"



enum outer_header_removal_values {
    OHR_GTP_U_UDP_IPv4 = 0,
    OHR_GTP_U_UDP_IPv6 = 1,
    OHR_UDP_IPv4 = 2,
    OHR_UDP_IPv6 = 3,
    OHR_IPv4 = 4,
    OHR_IPv6 = 5,
    OHR_GTP_U_UDP_IP = 6,
    OHR_VLAN_S_TAG = 7,
    OHR_S_TAG_C_TAG = 8,
};

// Possible optimizations:
// 0. Store SDFs in a separate map. PDR will have only id of corresponding SDF.
// 1. Combine SrcAddress.Type and DstAddress.Type into one __u8 field. Then to retrieve and put data will be used operators & and | .
// 2. Put all fields into one big structure. Sort in specific order to reduce paddings inside structure.

struct sdf_rules {
    struct sdf_filter sdf_filter;
    __u8 outer_header_removal;
    __u32 far_id;
    __u32 qer_id;
    __u32 urr1_id;
    __u32 urr2_id;
};

struct pdr_info {
    __u32 far_id;
    __u32 qer_id;
    __u32 urr1_id;
    __u32 urr2_id;
    __u8 outer_header_removal;
    __u8 sdf_mode; // 0 - no sdf, 1 - sdf only, 2 - sdf + default
    struct sdf_rules sdf_rules;
};

/* ipv4 -> PDR */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct pdr_info);
    __uint(max_entries, PDR_MAP_SIZE);
} pdr_map_downlink_ip4 SEC(".maps");

/* ipv6 -> PDR */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);
    __type(value, struct pdr_info);
    __uint(max_entries, PDR_MAP_SIZE);
} pdr_map_downlink_ip6 SEC(".maps");


/* teid -> PDR */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct pdr_info);
    __uint(max_entries, PDR_MAP_SIZE);
} pdr_map_teid_ip4 SEC(".maps");

enum far_action_mask {
    FAR_DROP = 0x01,
    FAR_FORW = 0x02,
    FAR_BUFF = 0x04,
    FAR_NOCP = 0x08,
    FAR_DUPL = 0x10,
    FAR_IPMA = 0x20,
    FAR_IPMD = 0x40,
    FAR_DFRT = 0x80,
};

enum outer_header_creation_values {
    OHC_GTP_U_UDP_IPv4 = 0x01,
    OHC_GTP_U_UDP_IPv6 = 0x02,
    OHC_UDP_IPv4 = 0x04,
    OHC_UDP_IPv6 = 0x08,
};

struct far_info {
    __u8 action;
    __u8 outer_header_creation;
    __u32 teid;
    __u32 remoteip;
    /* first octet DSCP value in the Type-of-Service, second octet shall contain the ToS/Traffic Class mask field, which shall be set to "0xFC". */
    __u16 transport_level_marking;
    /* 1 = emit plain GTP-U (no 5G PDU Session Container) toward an EPC peer;
     * 0 = keep the 5G ext header. Derived from the FAR's 3GPP Interface Type. */
    __u8 disable_gtp_psc;
    /* Duplication target, from the FAR Duplicating Parameters. A second GTP-U
     * copy of the matched packet goes to this TEID/peer when action has FAR_DUPL
     * set. Zero remoteip means no target is programmed. */
    __u8 dupl_outer_header_creation;
    __u32 dupl_teid;
    __u32 dupl_remoteip;
};

/* FAR ID -> FAR */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct far_info);
    __uint(max_entries, FAR_MAP_SIZE);
} far_map SEC(".maps");

/* bpf_redirect_map broadcast flags. These are UAPI from kernel 5.13, the same
 * floor the broadcast redirect itself needs; define them when the build headers
 * are older than the 5.13+ runtime that honours them. */
#ifndef BPF_F_BROADCAST
#define BPF_F_BROADCAST (1ULL << 3)
#endif
#ifndef BPF_F_EXCLUDE_INGRESS
#define BPF_F_EXCLUDE_INGRESS (1ULL << 4)
#endif

/* Interception mirror fan-out. A broadcast redirect into one of these copies
 * the frame to every device it holds, so each map carries exactly its own
 * direction's real egress device and the mirror device. Two maps because the
 * real egress device is fixed per direction. The value is bpf_devmap_val, not a
 * bare ifindex, so the mirror entry can also carry a per-device egress program
 * that re-encapsulates the copy toward the collector while the real-egress entry
 * stays a plain forward.
 *
 * A broadcast into an EMPTY devmap is not a no-op: the kernel finds no
 * destination and frees the frame, which would drop the very traffic we meant
 * to forward-and-copy. So the datapath must not broadcast until these maps are
 * populated. That is what mirror_enabled below gates: ConfigureMirror fills the
 * devmaps and only then sets the flag, so a FAR that asks to duplicate before
 * the mirror is wired forwards normally instead of black-holing the bearer. */
struct
{
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_devmap_val));
    __uint(max_entries, 2);
} mirror_devmap_dl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_devmap_val));
    __uint(max_entries, 2);
} mirror_devmap_ul SEC(".maps");

/* Set to 1 by ConfigureMirror once both devmaps hold their real-plus-mirror
 * entries. Until then the datapath never broadcasts, so an armed FAR forwards
 * normally rather than dropping the bearer into an empty devmap. */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} mirror_enabled SEC(".maps");
