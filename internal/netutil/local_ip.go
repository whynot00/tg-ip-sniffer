package netutil

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/google/gopacket/pcap"
)

// GetLocalIP возвращает IPv4-адрес интерфейса ifaceName.
// Сначала пробуем системное имя (Linux/macOS/Windows),
// затем — pcap-имя вида \Device\NPF_{GUID} (Windows).
func GetLocalIP(ifaceName string) (string, error) {
	if ifaceName == "" {
		return "", errors.New("не задано имя интерфейса")
	}

	// 1) Системное имя интерфейса
	if ip, ok := ipFromNet(ifaceName); ok {
		return ip, nil
	}

	// 2) Фолбэк для Windows / pcap-имён (\Device\NPF_{...})
	if runtime.GOOS == "windows" || looksLikeNPF(ifaceName) {
		if ip, ok := ipFromPcap(ifaceName); ok {
			return ip, nil
		}
	}

	return "", fmt.Errorf("IPv4-адрес не найден для интерфейса %q", ifaceName)
}

// ipFromNet ищет IPv4 по системному имени интерфейса.
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

// ipFromPcap ищет IPv4 по pcap-имени устройства.
// Полезно на Windows, где имена типа \Device\NPF_{GUID}.
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

// looksLikeNPF грубо определяет pcap-имя Windows.
func looksLikeNPF(name string) bool {
	n := strings.ToLower(name)
	// Скобки добавлены для ясности приоритетов &&/||
	return strings.HasPrefix(n, `\device\npf_`) || (strings.Contains(n, "{") && strings.Contains(n, "}"))
}

// validIPv4 возвращает строку IPv4, если это нормальный адрес,
// либо пустую строку для невалидных/служебных.
func validIPv4(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	// отбрасываем 0.0.0.0, 127.0.0.0/8, 169.254.0.0/16 (APIPA)
	if v4[0] == 0 || v4[0] == 127 || (v4[0] == 169 && v4[1] == 254) {
		return ""
	}
	return v4.String()
}
