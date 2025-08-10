package capture

import (
	"context"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/whynot00/tg-ip-sniffer/internal/filters"
	"github.com/whynot00/tg-ip-sniffer/internal/models"
	"github.com/whynot00/tg-ip-sniffer/internal/ports"
)

type NetworkReader struct {
	tracker *ports.Tracker
	handle  *pcap.Handle
	outCh   chan *models.IPRaw
}

func NewReader(ctx context.Context, ifaceName, appName string) *NetworkReader {
	r := &NetworkReader{
		tracker: ports.NewTracker(appName),
		outCh:   make(chan *models.IPRaw, 1024),
	}
	var err error
	r.handle, err = pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	go r.tracker.StartPolling(ctx)
	return r
}

func (r *NetworkReader) setBPF() error {
	filter := filters.BuildPorts(r.tracker.Snapshot())
	if filter == "" {
		// пустой фильтр — у pcap это валидно (снимаем ограничение)
		return r.handle.SetBPFFilter("")
	}
	return r.handle.SetBPFFilter(filter)
}

func (r *NetworkReader) Events() <-chan *models.IPRaw { return r.outCh }

func (r *NetworkReader) Start(ctx context.Context) {
	updateCh := r.tracker.Updates()
	packetSource := gopacket.NewPacketSource(r.handle, r.handle.LinkType())
	packets := packetSource.Packets()

	dirty := true
	debounce := time.NewTimer(time.Hour)
	_ = debounce.Stop

	apply := func() {
		if !dirty {
			return
		}
		_ = r.setBPF() // прежнее поведение — без строгой обработки
		dirty = false
	}

	for {
		select {
		case <-updateCh:
			dirty = true
			if !debounce.Stop() {
				select {
				case <-debounce.C:
				default:
				}
			}
			debounce.Reset(500 * time.Millisecond)

		case <-debounce.C:
			apply()

		case packet := <-packets:
			if packet == nil {
				close(r.outCh)
				return
			}

			if ipInfo := extractIPInfo(packet); ipInfo != nil {
				r.outCh <- ipInfo
			}
			apply()

		case <-ctx.Done():

			close(r.outCh)
			if r.handle != nil {
				r.handle.Close()
			}
			return
		}
	}
}
