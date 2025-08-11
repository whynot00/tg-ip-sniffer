// capture/reader_test.go
package capture

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/whynot00/tg-ip-sniffer/internal/ports"
)

type mockHandle struct {
	setCalls int32
	lastBPF  string
}

func (m *mockHandle) SetBPFFilter(s string) error {
	atomic.AddInt32(&m.setCalls, 1)
	m.lastBPF = s
	return nil
}

func (m *mockHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	// для Start() это может и не вызываться в юнит-тестах,
	// но чтобы тип удовлетворял интерфейсу — вернём заглушку.
	return nil, gopacket.CaptureInfo{}, errors.New("not implemented")
}
func (m *mockHandle) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (m *mockHandle) Close()                    {}

type mockWriter struct{ wrote int32 }

func (w *mockWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	atomic.AddInt32(&w.wrote, 1)
	return nil
}

func pktIPv4() gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &layers.IPv4{
		Version: 4, IHL: 5,
		SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{8, 8, 8, 8},
		Protocol: layers.IPProtocolUDP,
	})
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func TestRunLoop_CustomBPFApplied(t *testing.T) {
	tr := ports.NewTracker("dummy") // канал обновлений нам не важен
	h := &mockHandle{}
	w := &mockWriter{}
	r := newReaderForTest(tr, h, w)
	r.customBPF = "udp and port 53"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	packets := make(chan gopacket.Packet, 1)
	updates := make(chan struct{}, 1)

	// один пакет, чтобы apply() точно сработал
	packets <- pktIPv4()
	close(packets) // эмулируем завершение источника

	r.runLoop(ctx, packets, updates)

	if h.lastBPF != "udp and port 53" {
		t.Fatalf("want custom BPF, got %q", h.lastBPF)
	}
	if atomic.LoadInt32(&h.setCalls) == 0 {
		t.Fatal("SetBPFFilter was not called")
	}
}

func TestRunLoop_Debounce(t *testing.T) {
	tr := ports.NewTracker("dummy")
	h := &mockHandle{}
	r := newReaderForTest(tr, h, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	packets := make(chan gopacket.Packet) // пусто, чтобы не триггерить apply() через пакеты
	updates := make(chan struct{}, 10)

	for i := 0; i < 5; i++ {
		updates <- struct{}{}
	}

	go func() {
		time.Sleep(600 * time.Millisecond) // > 500ms окна дебаунса
		cancel()
	}()

	r.runLoop(ctx, packets, updates)

	if atomic.LoadInt32(&h.setCalls) != 1 {
		t.Fatalf("want 1 SetBPFFilter call, got %d", h.setCalls)
	}
}

func TestRunLoop_DumpWrite(t *testing.T) {
	tr := ports.NewTracker("dummy")
	h := &mockHandle{}
	w := &mockWriter{}
	r := newReaderForTest(tr, h, w)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	packets := make(chan gopacket.Packet, 1)
	updates := make(chan struct{})

	packets <- pktIPv4()
	close(packets)

	r.runLoop(ctx, packets, updates)

	if atomic.LoadInt32(&w.wrote) == 0 {
		t.Fatal("expected at least one WritePacket")
	}
}

func TestRunLoop_ClosesOutCh_OnNilPacket(t *testing.T) {
	tr := ports.NewTracker("dummy")
	h := &mockHandle{}
	r := newReaderForTest(tr, h, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	packets := make(chan gopacket.Packet, 1)
	updates := make(chan struct{})

	// nil-пакет → ветка закрытия
	packets <- nil

	done := make(chan struct{})
	go func() {
		r.runLoop(ctx, packets, updates)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("runLoop did not exit after nil packet")
	}
}
