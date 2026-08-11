#!/usr/bin/env bash
# Native-XDP functional rig for the SORM interception mirror.
#
# It proves, on a real kernel, that a native broadcast redirect delivers the
# frame to both the real egress device and the mirror device, and that the
# devmap egress program (li_mirror_egress.c) re-encapsulates only the mirror
# copy toward the collector while the real-egress copy stays byte-identical.
# bpf_prog_test_run cannot perform the redirect, and generic XDP does not
# isolate the per-device copies, so this needs native XDP with a proper traffic
# generator: a flood ping from a peer namespace produces headroom-correct skbs
# that drive the veth native RX path.
#
# Run in a privileged Linux container (amd64, to match production) with a kernel
# >= 5.13:
#   docker run --rm --platform linux/amd64 --privileged \
#     -v "$PWD:/eupf" -w /eupf golang:1.22.7-bullseye \
#     bash test/xdp-mirror-rig/run.sh
set -e

REPO=$(cd "$(dirname "$0")/../.." && pwd)
RIG="$REPO/test/xdp-mirror-rig"

apt-get update -qq >/dev/null 2>&1
apt-get install --no-install-recommends -y -qq \
    clang llvm gcc-multilib libbpf-dev linux-libc-dev iproute2 iputils-ping >/dev/null 2>&1

echo "kernel $(uname -r) container-arch $(uname -m)"

# Build the eUPF egress object (bpf2go) and the clone generator.
( cd "$REPO" && go generate ./cmd/ebpf/ >/dev/null 2>&1 )
ARCH_INC=/usr/include/$(uname -m)-linux-gnu
clang -O2 -g -target bpf -I"$ARCH_INC" -c "$RIG/clone_dv.c" -o "$RIG/clone_dv.o"
( cd "$RIG" && go mod tidy >/dev/null 2>&1 )

mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

attach_pass() { # dev [netns]
    local dev=$1 ns=$2 pfx=""
    [ -n "$ns" ] && pfx="ip netns exec $ns"
    if $pfx ip link set dev "$dev" xdpdrv obj "$RIG/clone_dv.o" sec xdp/pass 2>/dev/null; then
        echo "  $dev: xdp_pass native"
    else
        $pfx ip link set dev "$dev" xdpgeneric obj "$RIG/clone_dv.o" sec xdp/pass
        echo "  WARNING $dev: xdp_pass fell back to generic; native ndo_xdp_xmit needs the peer NAPI, a RIG_FAIL here is the environment, not the datapath"
    fi
}

cleanup() { ip netns del src 2>/dev/null || true; ip link del vout 2>/dev/null || true; ip link del vmir 2>/dev/null || true; }
trap cleanup EXIT

# Ingress veth: the pinger lives in a namespace, the clone program on the root end.
ip netns add src
ip link add vin type veth peer name vin_p
ip link set vin_p netns src
ip addr add 10.0.0.1/24 dev vin; ip link set vin up
ip netns exec src ip addr add 10.0.0.2/24 dev vin_p
ip netns exec src ip link set vin_p up; ip netns exec src ip link set lo up
attach_pass vin_p src

# Real egress and mirror devices. A native redirect via ndo_xdp_xmit only lands
# on a veth whose peer runs XDP, so arm the peers with a pass program.
ip link add vout type veth peer name vout_p
ip link add vmir type veth peer name vmir_p
for d in vout vout_p vmir vmir_p; do ip link set $d up; done
attach_pass vout_p; attach_pass vmir_p

# The downlink egress program does an OUTPUT fib lookup for the collector out of
# the mirror device, so give it a route and a static neighbour; without them the
# lookup fails and the program correctly drops the copy.
ip route add 203.0.113.7/32 dev vmir
ip neigh replace 203.0.113.7 dev vmir lladdr 02:00:00:00:00:99 nud permanent

export VIN=vin VOUT=vout VMIR=vmir VOUT_P=vout_p VMIR_P=vmir_p
export LI_OBJ="$REPO/cmd/ebpf/limirroregress_bpf.o" CLONE_OBJ="$RIG/clone_dv.o"
( cd "$RIG" && go run harness.go )
