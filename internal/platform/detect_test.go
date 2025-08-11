package platform

import (
	"testing"

	"github.com/google/gopacket/pcap"
)

func TestNormalize(t *testing.T) {
	in := "Wi‑Fi—Adapter–Test"
	got := normalize(in)
	if got != "wi-fi-adapter-test" {
		t.Fatalf("normalize(%q) = %q", in, got)
	}
}

func TestHasGoodIPv4(t *testing.T) {
	tests := []struct {
		name string
		in   []pcap.InterfaceAddress
		ok   bool
	}{
		{"nil", nil, false},
		{"loopback", []pcap.InterfaceAddress{{IP: []byte{127, 0, 0, 1}}}, false},
		{"apipa", []pcap.InterfaceAddress{{IP: []byte{169, 254, 1, 2}}}, false},
		{"zero", []pcap.InterfaceAddress{{IP: []byte{0, 0, 0, 0}}}, false},
		{"good", []pcap.InterfaceAddress{{IP: []byte{192, 168, 1, 10}}}, true},
	}
	for _, tt := range tests {
		_, ok := hasGoodIPv4(tt.in)
		if ok != tt.ok {
			t.Fatalf("%s: want %v, got %v", tt.name, tt.ok, ok)
		}
	}
}

func TestScoreDesc(t *testing.T) {
	if scoreDesc("VMware Virtual Ethernet Adapter") >= 0 {
		t.Fatal("bad description should decrease score")
	}
	if scoreDesc("Intel(R) Ethernet Controller") <= 0 {
		t.Fatal("good description should increase score")
	}
}
