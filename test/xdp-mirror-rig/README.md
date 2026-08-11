# Native-XDP mirror rig

A functional test for the SORM interception datapath: the broadcast clone in
`n3n6_entrypoint.c` and the devmap egress program in `li_mirror_egress.c`.

`bpf_prog_test_run` runs a program and hands back the action, but it does not
perform `XDP_REDIRECT`, so it cannot show that the clone reached a device or that
the egress program ran on it. This rig does, on a real kernel.

## What it asserts

Three veth pairs stand in for the ingress link, the real egress device, and the
mirror device. `clone_bcast` is attached in native XDP on the ingress veth and
broadcast-redirects into a two-entry devmap holding the real egress device and
the mirror device; the mirror entry carries the `li_mirror_dl` egress program
with a collector of `203.0.113.7` (a non-palindromic address so an endianness
bug in the collector path shows on the wire). A burst of UDP datagrams from the
peer namespace generates the traffic; GTP-U rides UDP, so this is the
production-shaped packet, and each datagram carries a kernel-computed, non-zero
outer UDP checksum. The check reads the whole burst on both egress peers, not
just the first frame, and requires:

- every real-egress copy keeps its original outer destination (`10.0.0.1`), a
  valid IPv4 header checksum, and the sender's non-zero UDP checksum, and
- every mirror copy has its outer destination rewritten to the collector, a
  recomputed valid IPv4 checksum, and a zeroed outer UDP checksum (rewriting the
  destination invalidates the UDP pseudo-header checksum, so the egress program
  zeroes it, which is legal for IPv4 UDP).

The rewrite confined to the mirror copy is the per-device isolation the datapath
relies on. The collector needs a route out of the mirror device (the egress
program does an OUTPUT fib lookup and drops the copy on failure), which `run.sh`
adds along with a static neighbour.

## Why native XDP, and why a UDP generator

Generic XDP does not isolate the per-device copies: the egress program's rewrite
leaks onto the real-egress copy. Native XDP keeps each redirected `xdp_frame`
independent, so the mirror re-encapsulation cannot corrupt the forwarded packet.
This makes native XDP a correctness requirement for the mirror, not only a
throughput one.

Native veth RX is driven by headroom-correct frames. A raw `AF_PACKET` inject
has no XDP headroom and does not reliably reach the native RX path, so the rig
generates traffic with the kernel's own UDP stack (proper-headroom skbs). A
native redirect via `ndo_xdp_xmit` only lands on a veth whose peer runs an XDP
program, so the egress peers are armed with a pass program.

## Running it

Needs a privileged Linux container with a kernel >= 5.13, built for amd64 to
match production:

```
docker run --rm --platform linux/amd64 --privileged \
  -v "$PWD:/eupf" -w /eupf golang:1.22.7-bullseye \
  bash test/xdp-mirror-rig/run.sh
```

A pass prints `RIG_PASS`.
