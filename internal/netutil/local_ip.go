package netutil

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/google/gopacket/pcap"
)

func GetLocalIP(ifaceName string) (string, error) {
	if ifaceName == "" {
		return "", fmt.Errorf("не задано имя интерфейса")
	}

	// 1) Пытаемся как обычно: системное имя (Linux/macOS/Windows с Alias)
	if ip, ok := ipFromNet(ifaceName); ok {
		return ip, nil
	}

	// 2) Фолбэк для Windows / pcap-имен (\Device\NPF_{...})
	if runtime.GOOS == "windows" || looksLikeNPF(ifaceName) {
		if ip, ok := ipFromPcap(ifaceName); ok {
			return ip, nil
		}
	}

	return "", fmt.Errorf("IPv4-адрес не найден для интерфейса %s", ifaceName)
}

func ipFromNet(name string) (string, bool) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", false
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if v4 := validIPv4(ipnet.IP); v4 != "" {
				return v4, true
			}
		}
	}
	return "", false
}

func ipFromPcap(pcapName string) (string, bool) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", false
	}
	for _, d := range devs {
		if d.Name != pcapName {
			continue
		}
		for _, a := range d.Addresses {
			if v4 := validIPv4(a.IP); v4 != "" {
				return v4, true
			}
		}
		return "", false
	}
	return "", false
}

func looksLikeNPF(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, `\device\npf_`) || strings.Contains(n, "{") && strings.Contains(n, "}")
}

func validIPv4(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	// фильтруем мусорные диапазоны: 0.0.0.0, 127.0.0.0/8, 169.254.0.0/16
	if v4[0] == 0 || v4[0] == 127 || (v4[0] == 169 && v4[1] == 254) {
		return ""
	}
	return v4.String()
}
