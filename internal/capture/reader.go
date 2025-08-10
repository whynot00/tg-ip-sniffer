package capture

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/whynot00/tg-ip-sniffer/internal/models"
	"github.com/whynot00/tg-ip-sniffer/internal/network"
)

type NetworkReader struct {
	interfaces *network.Ports
	handle     *pcap.Handle
	outCh      chan *models.IPRaw
}

func NewReader(ctx context.Context, ifaceName string) *NetworkReader {

	reader := &NetworkReader{
		interfaces: network.LoadPorts("Telegram"),
		outCh:      make(chan *models.IPRaw, 1024),
	}

	var err error
	reader.handle, err = pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	go reader.interfaces.StartPooling(ctx)

	return reader
}

func (r *NetworkReader) SetBPF() error {
	return r.handle.SetBPFFilter(fmt.Sprintf("(%s)", strings.Join(r.interfaces.Snapshot(), " or ")))
}

func (r *NetworkReader) Events() <-chan *models.IPRaw {

	return r.outCh
}

func (r *NetworkReader) Start(ctx context.Context) {

	updateCh := r.interfaces.Updates()
	packetSource := gopacket.NewPacketSource(r.handle, r.handle.LinkType())
	packets := packetSource.Packets()

	dirty := true
	debounce := time.NewTimer(time.Hour)
	_ = debounce.Stop

	apply := func() {
		if !dirty {
			return
		}

		if err := r.SetBPF(); err != nil {

			return
		}

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
				return
			}

			ipInfo := extractIPInfo(packet)

			if ipInfo == nil {
				continue
			}

			r.outCh <- ipInfo
			apply()

		case <-ctx.Done():
			return
		}
	}

}
