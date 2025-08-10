package capture

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/whynot00/tg-ip-sniffer/internal/models"
)

func extractIPInfo(packet gopacket.Packet) *models.IPRaw {
	if ipv4 := packet.Layer(layers.LayerTypeIPv4); ipv4 != nil {
		ip := ipv4.(*layers.IPv4)

		ts := time.Now()
		if meta := packet.Metadata(); meta != nil {
			// чуть точнее, но семантика та же
			if !meta.CaptureInfo.Timestamp.IsZero() {
				ts = meta.CaptureInfo.Timestamp
			}
		}

		return &models.IPRaw{
			Time:     ts,
			IPSrc:    append(net.IP(nil), ip.SrcIP...),
			IPDst:    append(net.IP(nil), ip.DstIP...),
			Protocol: ip.Protocol.String(),
		}
	}
	return nil
}
