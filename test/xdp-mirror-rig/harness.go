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

// devmapVal mirrors the kernel's struct bpf_devmap_val: a target ifindex plus an
// optional per-device egress program fd.
type devmapVal struct {
	Ifindex uint32
	BpfProg uint32
}

type mirrorCfg struct {
	CollectorIP uint32 // network order
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
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3})
	return fd
}

// firstICMPDst reads frames until it finds an IPv4 ICMP echo request and returns
// its outer destination address, or "" on timeout.
func firstICMPDst(fd int) string {
	buf := make([]byte, 2048)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return ""
		}
		if n < 34 {
			continue
		}
		if buf[12] != 0x08 || buf[13] != 0x00 { // not IPv4
			continue
		}
		if buf[23] != 1 { // not ICMP
			continue
		}
		return net.IP(buf[30:34]).String()
	}
	return ""
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
	collector := binary.LittleEndian.Uint32(net.ParseIP("9.9.9.9").To4())
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

	// Native XDP on the ingress device. The generator (ping from the peer netns)
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

	// Generator: flood-ping vin's address from the peer namespace. The echo
	// requests arrive at vin's native XDP RX and are broadcast-cloned.
	ping := exec.Command("ip", "netns", "exec", "src", "ping", "-f", "-w", "2", "10.0.0.1")
	_ = ping.Run() // 100% loss is expected (requests are redirected, never replied)

	realDst := firstICMPDst(capReal)
	mirDst := firstICMPDst(capMir)
	fmt.Printf("real-egress outer dst = %q (want 10.0.0.1, untouched)\n", realDst)
	fmt.Printf("mirror     outer dst = %q (want 9.9.9.9, re-encapped to collector)\n", mirDst)
	if realDst == "10.0.0.1" && mirDst == "9.9.9.9" {
		fmt.Println("RIG_PASS: native XDP broadcast clone delivered both copies; egress program re-encapped only the mirror copy")
	} else {
		fmt.Println("RIG_FAIL")
		os.Exit(1)
	}
}
