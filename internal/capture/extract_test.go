package capture

import (
	"slices"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// собираем минимальный IPv4-пакет
func makeIPv4Packet() gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    []byte{192, 168, 1, 10},
		DstIP:    []byte{149, 154, 167, 51},
		Protocol: layers.IPProtocolTCP,
	}
	_ = gopacket.SerializeLayers(buf, opts, ip)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func TestExtractIPInfo_Basic(t *testing.T) {
	pkt := makeIPv4Packet()

	ev := extractIPInfo(pkt)
	if ev == nil {
		t.Fatal("expected non-nil")
	}
	if got := ev.IPSrc.String(); got != "192.168.1.10" {
		t.Fatalf("src = %s, want 192.168.1.10", got)
	}
	if got := ev.IPDst.String(); got != "149.154.167.51" {
		t.Fatalf("dst = %s, want 149.154.167.51", got)
	}
	if ev.Protocol != "TCP" {
		t.Fatalf("proto = %s, want TCP", ev.Protocol)
	}
	// Время: extractIPInfo использует CaptureInfo.Timestamp, если он есть,
	// иначе time.Now(). Мы не прокидываем timestamp, так что просто проверим,
	// что оно "похоже на сейчас".
	if time.Since(ev.Time) > 2*time.Second {
		t.Fatalf("unexpected timestamp drift: %v", time.Since(ev.Time))
	}
}

func TestCopyIP_UsesSlicesClone(t *testing.T) {
	in := []byte{1, 2, 3}
	out := copyIP(in)
	if !slices.Equal(in, out) {
		t.Fatalf("expected equal content")
	}
	// меняем исходный — копия не должна измениться
	in[0] = 9
	if out[0] == 9 {
		t.Fatalf("copyIP must create independent slice")
	}
}
