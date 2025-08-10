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
		return &models.IPRaw{
			Time:     time.Now(),
			IPSrc:    append(net.IP(nil), ip.SrcIP...),
			IPDst:    append(net.IP(nil), ip.DstIP...),
			Protocol: ip.Protocol.String(),
		}
	}

	return nil
}
