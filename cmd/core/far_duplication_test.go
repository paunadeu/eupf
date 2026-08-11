package core

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/edgecomllc/eupf/cmd/ebpf"
	"github.com/wmnsk/go-pfcp/ie"
)

const (
	ohcGTPUUDPIPv4 = 0x0100
	ohcGTPUUDPIPv6 = 0x0200
	applyFORW      = 0x02
	applyDUPL      = 0x10
)

// A duplicating FAR with an IPv4 collector must land its mirror target in the
// FAR record so the datapath gate arms.
func TestComposeFarInfo_DuplicatingIPv4Collector(t *testing.T) {
	far := ie.NewCreateFAR(
		ie.NewFARID(1),
		ie.NewApplyAction(applyFORW|applyDUPL),
		ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewOuterHeaderCreation(ohcGTPUUDPIPv4, 0x1111, "8.8.8.8", "", 0, 0, 0),
		),
		ie.NewDuplicatingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceLIFunction),
			ie.NewOuterHeaderCreation(ohcGTPUUDPIPv4, 0x2222, "10.9.9.9", "", 0, 0, 0),
		),
	)

	got, err := composeFarInfo(far, ebpf.FarInfo{})
	if err != nil {
		t.Fatalf("composeFarInfo returned error for an IPv4 collector: %v", err)
	}
	if got.Action&applyDUPL == 0 {
		t.Errorf("Action = %#x, want the DUPL bit set", got.Action)
	}
	if got.DuplTeid != 0x2222 {
		t.Errorf("DuplTeid = %#x, want 0x2222", got.DuplTeid)
	}
	want := binary.LittleEndian.Uint32(net.ParseIP("10.9.9.9").To4())
	if got.DuplRemoteIP != want {
		t.Errorf("DuplRemoteIP = %#x, want %#x (10.9.9.9)", got.DuplRemoteIP, want)
	}
}

// An IPv6 collector is not supported yet. It must fail the same way the primary
// forwarding path does rather than be accepted as a silently un-intercepted
// session.
func TestComposeFarInfo_DuplicatingIPv6CollectorErrors(t *testing.T) {
	far := ie.NewCreateFAR(
		ie.NewFARID(1),
		ie.NewApplyAction(applyFORW|applyDUPL),
		ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewOuterHeaderCreation(ohcGTPUUDPIPv4, 0x1111, "8.8.8.8", "", 0, 0, 0),
		),
		ie.NewDuplicatingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceLIFunction),
			ie.NewOuterHeaderCreation(ohcGTPUUDPIPv6, 0x2222, "", "2001:db8::1", 0, 0, 0),
		),
	)

	if _, err := composeFarInfo(far, ebpf.FarInfo{}); err == nil {
		t.Error("composeFarInfo accepted an IPv6 collector; want an error so the session is not silently un-intercepted")
	}
}

// DUPL set but no Duplicating Parameters must not error (the FAR still forwards)
// but must leave no mirror target, so the datapath gate stays closed.
func TestComposeFarInfo_DuplWithoutParametersLeavesNoTarget(t *testing.T) {
	far := ie.NewCreateFAR(
		ie.NewFARID(1),
		ie.NewApplyAction(applyFORW|applyDUPL),
		ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewOuterHeaderCreation(ohcGTPUUDPIPv4, 0x1111, "8.8.8.8", "", 0, 0, 0),
		),
	)

	got, err := composeFarInfo(far, ebpf.FarInfo{})
	if err != nil {
		t.Fatalf("composeFarInfo errored on a FAR without Duplicating Parameters: %v", err)
	}
	if got.DuplRemoteIP != 0 {
		t.Errorf("DuplRemoteIP = %#x, want 0 (no target programmed)", got.DuplRemoteIP)
	}
}
