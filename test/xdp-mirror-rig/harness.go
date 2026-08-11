package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// A non-palindromic collector so an endianness bug in the collector_ip path
// shows up on the wire (an all-equal address like 9.9.9.9 would hide it).
const collectorIP = "203.0.113.7"

// devmapVal mirrors the kernel's struct bpf_devmap_val: a target ifindex plus an
// optional per-device egress program fd.
type devmapVal struct {
	Ifindex uint32
	BpfProg uint32
}

type mirrorCfg struct {
	CollectorIP uint32
}

func ifindex(name string) int {
	i, err := net.InterfaceByName(name)
	if err != nil {
		panic(fmt.Sprintf("iface %s: %v", name, err))
	}
	return i.Index
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

func openCapture(idx int) int {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: idx}); err != nil {
		panic(err)
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	return fd
}

// ipv4ChecksumOK folds the 20-byte IPv4 header; a valid header sums to 0xffff.
func ipv4ChecksumOK(hdr []byte) bool {
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum == 0xffff
}

type capture struct {
	total      int
	dsts       map[string]int
	badIPSum   int
	udpZero    int // frames whose outer UDP checksum field is zero
	udpNonspec int // frames whose outer UDP checksum field is non-zero
}

// collectUDP reads every IPv4/UDP frame seen on the socket within the window,
// tallying outer destinations, any packet whose IPv4 header checksum does not
// verify, and how many carry a zero vs non-zero outer UDP checksum. GTP-U rides
// UDP, so this is the production-shaped case: the mirror copy must have its UDP
// checksum zeroed after the destination rewrite, while the real-egress copy
// keeps the sender's original non-zero checksum. Reading the whole burst, not
// just the first frame, is what lets the rig catch an intermittent bug.
func collectUDP(fd int) capture {
	c := capture{dsts: map[string]int{}}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			continue // timeout tick; keep draining until the deadline
		}
		if n < 42 || buf[12] != 0x08 || buf[13] != 0x00 || buf[23] != 17 {
			continue // not IPv4 UDP
		}
		c.total++
		c.dsts[net.IP(buf[30:34]).String()]++
		if !ipv4ChecksumOK(buf[14:34]) {
			c.badIPSum++
		}
		if buf[40] == 0 && buf[41] == 0 {
			c.udpZero++
		} else {
			c.udpNonspec++
		}
	}
	return c
}

func onlyDst(c capture) string {
	if len(c.dsts) == 1 {
		for d := range c.dsts {
			return d
		}
	}
	return fmt.Sprintf("%v", c.dsts)
}

func main() {
	vin := ifindex(os.Getenv("VIN"))
	vout := ifindex(os.Getenv("VOUT"))
	vmir := ifindex(os.Getenv("VMIR"))
	voutP := ifindex(os.Getenv("VOUT_P"))
	vmirP := ifindex(os.Getenv("VMIR_P"))

	liObj := os.Getenv("LI_OBJ")
	if liObj == "" {
		liObj = "../../cmd/ebpf/limirroregress_bpf.o"
	}
	cloneObj := os.Getenv("CLONE_OBJ")
	if cloneObj == "" {
		cloneObj = "clone_dv.o"
	}

	// Egress program + its config map (the re-encap leg).
	liSpec, err := ebpf.LoadCollectionSpec(liObj)
	if err != nil {
		panic(err)
	}
	li, err := ebpf.NewCollection(liSpec)
	if err != nil {
		panic(err)
	}
	defer li.Close()
	egress := li.Programs["li_mirror_dl"]
	collector := binary.NativeEndian.Uint32(net.ParseIP(collectorIP).To4())
	if err := li.Maps["mirror_cfg_dl"].Put(uint32(0), mirrorCfg{CollectorIP: collector}); err != nil {
		panic(err)
	}

	// Broadcast clone program + its devmap.
	clSpec, err := ebpf.LoadCollectionSpec(cloneObj)
	if err != nil {
		panic(err)
	}
	cl, err := ebpf.NewCollection(clSpec)
	if err != nil {
		panic(err)
	}
	defer cl.Close()
	dm := cl.Maps["mirror"]
	if err := dm.Put(uint32(0), devmapVal{Ifindex: uint32(vout)}); err != nil {
		panic(fmt.Sprintf("devmap put real: %v", err))
	}
	if err := dm.Put(uint32(1), devmapVal{Ifindex: uint32(vmir), BpfProg: uint32(egress.FD())}); err != nil {
		panic(fmt.Sprintf("devmap put mirror+prog: %v", err))
	}

	// Native XDP on the ingress device. The generator (UDP from the peer netns)
	// produces proper-headroom skbs, which drive the veth native RX path, unlike
	// a raw AF_PACKET inject.
	lnk, err := link.AttachXDP(link.XDPOptions{Program: cl.Programs["clone_bcast"], Interface: vin, Flags: link.XDPDriverMode})
	if err != nil {
		panic(fmt.Sprintf("attach clone native on vin: %v", err))
	}
	defer lnk.Close()
	fmt.Println("clone_bcast attached native on vin")

	capReal := openCapture(voutP)
	capMir := openCapture(vmirP)
	time.Sleep(200 * time.Millisecond)

	// Generator: UDP datagrams toward vin's address from the peer namespace. GTP-U
	// rides UDP, so this is the production-shaped packet. One ping first warms the
	// ARP entry; then a burst of UDP, each with a kernel-computed (non-zero) outer
	// UDP checksum, arrives at vin's native XDP RX and is broadcast-cloned.
	_ = exec.Command("ip", "netns", "exec", "src", "ping", "-c", "1", "-W", "1", "10.0.0.1").Run()
	gen := exec.Command("ip", "netns", "exec", "src", "bash", "-c",
		"for i in $(seq 300); do printf test > /dev/udp/10.0.0.1/9999; done")
	_ = gen.Run()

	real := collectUDP(capReal)
	mir := collectUDP(capMir)
	fmt.Printf("real-egress: %d UDP frames, dst=%s, bad-ip-csum=%d, udp-csum zero/nonzero=%d/%d\n",
		real.total, onlyDst(real), real.badIPSum, real.udpZero, real.udpNonspec)
	fmt.Printf("mirror     : %d UDP frames, dst=%s, bad-ip-csum=%d, udp-csum zero/nonzero=%d/%d\n",
		mir.total, onlyDst(mir), mir.badIPSum, mir.udpZero, mir.udpNonspec)

	// Real-egress copy: untouched (original destination, sender's non-zero UDP
	// checksum preserved on at least some frames, valid IPv4 header).
	realOK := real.total > 0 && len(real.dsts) == 1 && real.dsts["10.0.0.1"] == real.total &&
		real.badIPSum == 0 && real.udpNonspec > 0
	// Mirror copy: re-pointed at the collector, IPv4 checksum recomputed, and the
	// outer UDP checksum zeroed on every frame so the collector accepts it.
	mirOK := mir.total > 0 && len(mir.dsts) == 1 && mir.dsts[collectorIP] == mir.total &&
		mir.badIPSum == 0 && mir.udpNonspec == 0 && mir.udpZero == mir.total
	if realOK && mirOK {
		fmt.Println("RIG_PASS: real-egress copies untouched (dst + non-zero UDP csum preserved); every mirror copy re-encapped to the collector with a valid IPv4 checksum and a zeroed UDP checksum")
	} else {
		fmt.Println("RIG_FAIL")
		os.Exit(1)
	}
}
