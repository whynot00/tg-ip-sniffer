package capture

import (
	"net"
	"slices"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/whynot00/tg-ip-sniffer/internal/models"
)

// extractIPInfo вытаскивает базовую информацию об IPv4-пакете и возвращает её
// в виде models.IPRaw. Для не-IPv4 пакетов возвращает nil.
// Поведение соответствует исходному коду.
func extractIPInfo(packet gopacket.Packet) *models.IPRaw {
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil
	}
	ip := ipv4Layer.(*layers.IPv4)

	return &models.IPRaw{
		Time:     captureTime(packet),
		IPSrc:    copyIP(ip.SrcIP),
		IPDst:    copyIP(ip.DstIP),
		Protocol: ip.Protocol.String(),
	}
}

// captureTime возвращает временную метку из pcap-заголовка, если она есть,
// иначе — текущее время (как в исходной версии).
func captureTime(pkt gopacket.Packet) time.Time {
	if m := pkt.Metadata(); m != nil && !m.CaptureInfo.Timestamp.IsZero() {
		return m.CaptureInfo.Timestamp
	}
	return time.Now()
}

// copyIP создаёт независимую копию IP-адреса.
func copyIP(in net.IP) net.IP {
	if in == nil {
		return nil
	}
	return slices.Clone(in)
}
