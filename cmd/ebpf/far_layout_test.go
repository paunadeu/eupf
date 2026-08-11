package ebpf

import (
	"testing"
	"unsafe"
)

// The datapath reads FAR entries as the C struct far_info, while the control
// plane writes them as the hand-written FarInfo via an unsafe pointer memcpy.
// The two must agree on size and on every field offset, or a mirror target
// written from Go lands on the wrong bytes in the kernel map. bpf2go derives
// IpEntrypointFarInfo directly from the C struct, so it stands in for the
// datapath's view here.
func TestFarInfoLayoutMatchesGenerated(t *testing.T) {
	var hand FarInfo
	var gen IpEntrypointFarInfo

	if got, want := unsafe.Sizeof(hand), unsafe.Sizeof(gen); got != want {
		t.Fatalf("FarInfo size = %d, generated far_info size = %d", got, want)
	}

	checks := []struct {
		name       string
		hand, gen  uintptr
	}{
		{"action", unsafe.Offsetof(hand.Action), unsafe.Offsetof(gen.Action)},
		{"outer_header_creation", unsafe.Offsetof(hand.OuterHeaderCreation), unsafe.Offsetof(gen.OuterHeaderCreation)},
		{"teid", unsafe.Offsetof(hand.Teid), unsafe.Offsetof(gen.Teid)},
		{"remoteip", unsafe.Offsetof(hand.RemoteIP), unsafe.Offsetof(gen.Remoteip)},
		{"transport_level_marking", unsafe.Offsetof(hand.TransportLevelMarking), unsafe.Offsetof(gen.TransportLevelMarking)},
		{"disable_gtp_psc", unsafe.Offsetof(hand.DisableGTPPSC), unsafe.Offsetof(gen.DisableGtpPsc)},
		{"dupl_outer_header_creation", unsafe.Offsetof(hand.DuplOuterHeaderCreation), unsafe.Offsetof(gen.DuplOuterHeaderCreation)},
		{"dupl_teid", unsafe.Offsetof(hand.DuplTeid), unsafe.Offsetof(gen.DuplTeid)},
		{"dupl_remoteip", unsafe.Offsetof(hand.DuplRemoteIP), unsafe.Offsetof(gen.DuplRemoteip)},
	}
	for _, c := range checks {
		if c.hand != c.gen {
			t.Errorf("field %s: FarInfo offset %d, generated offset %d", c.name, c.hand, c.gen)
		}
	}
}
