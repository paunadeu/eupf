//go:build mirror_rig

package ebpf

import (
	"encoding/binary"
	"net"
	"os/exec"
	"testing"
)

// TestConfigureMirror loads the real pipeline objects, wires the interception
// fan-out, and reads the maps back to confirm the collector config and the
// devmap entries (including the egress program on the mirror slot) landed. It
// needs root and the BPF filesystem, so it is gated behind the mirror_rig build
// tag and run on the Linux XDP rig, not in the default suite.
func TestConfigureMirror(t *testing.T) {
	if out, err := exec.Command("ip", "link", "add", "mtest", "type", "veth", "peer", "name", "mtest_p").CombinedOutput(); err != nil {
		t.Fatalf("create veth: %v: %s", err, out)
	}
	defer exec.Command("ip", "link", "del", "mtest").Run()
	_ = exec.Command("ip", "link", "set", "mtest", "up").Run()

	iface, err := net.InterfaceByName("mtest")
	if err != nil {
		t.Fatalf("lookup veth: %v", err)
	}
	idx := uint32(iface.Index)

	o := NewBpfObjects()
	if err := o.Load(); err != nil {
		t.Fatalf("load objects: %v", err)
	}
	defer o.Close()

	collector := net.ParseIP("9.9.9.9")
	if err := o.ConfigureMirror(collector, idx, idx, idx, idx); err != nil {
		t.Fatalf("configure mirror: %v", err)
	}

	var cfg LiMirrorEgressMirrorCfg
	if err := o.MirrorCfgDl.Lookup(uint32(0), &cfg); err != nil {
		t.Fatalf("lookup collector config: %v", err)
	}
	if want := binary.LittleEndian.Uint32(collector.To4()); cfg.CollectorIp != want {
		t.Errorf("collector = %#x, want %#x", cfg.CollectorIp, want)
	}

	var real, mirror mirrorDevmapValue
	if err := o.MirrorDevmapDl.Lookup(uint32(0), &real); err != nil {
		t.Fatalf("lookup real slot: %v", err)
	}
	if real.Ifindex != idx {
		t.Errorf("real slot ifindex = %d, want %d", real.Ifindex, idx)
	}
	if err := o.MirrorDevmapDl.Lookup(uint32(1), &mirror); err != nil {
		t.Fatalf("lookup mirror slot: %v", err)
	}
	if mirror.Ifindex != idx {
		t.Errorf("mirror slot ifindex = %d, want %d", mirror.Ifindex, idx)
	}
	// On lookup the devmap returns the egress program's id, not the fd; a nonzero
	// value confirms the downlink mirror slot carries the re-encap program.
	if mirror.BpfProgFD == 0 {
		t.Error("mirror slot has no egress program attached")
	}
}
