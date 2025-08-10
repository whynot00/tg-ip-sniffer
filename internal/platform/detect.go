package platform

import (
	"runtime"
	"strings"
	"unicode"

	"github.com/google/gopacket/pcap"
)

// TelegramProcessName возвращает имя процесса Telegram под текущей ОС.
func TelegramProcessName() string {
	if runtime.GOOS == "windows" {
		return "Telegram.exe"
	}
	return "Telegram"
}

func normalize(s string) string {
	// привести к нижнему и заменить «фигурные» дефисы на обычный
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		switch r {
		case '‑', '–', '—': // non-breaking, en/em dashes
			return '-'
		default:
			return unicode.ToLower(r)
		}
	}, s)
	return s
}

func hasGoodIPv4(addrs []pcap.InterfaceAddress) (string, bool) {
	for _, a := range addrs {
		ip := a.IP
		if ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		// фильтруем мусор: 169.254.0.0/16 (APIPA), 127.0.0.0/8, 0.0.0.0
		if v4[0] == 169 && v4[1] == 254 {
			continue
		}
		if v4[0] == 127 || v4[0] == 0 {
			continue
		}
		// нормальный приватный или белый — годится
		return v4.String(), true
	}
	return "", false
}

func scoreDesc(desc string) int {
	desc = normalize(desc)

	good := []string{"wi-fi", "wifi", "wireless", "ethernet", "realtek", "intel", "qualcomm", "lan", "беспровод"}
	bad := []string{
		"loopback", "npcap loopback", "virtualbox", "vmware", "hyper-v", "vethernet",
		"docker", "wsl", "tailscale", "zerotier", "tap", "tunnel", "isatap", "teredo", "bluetooth",
	}

	score := 0
	for _, b := range bad {
		if strings.Contains(desc, b) {
			score -= 5
		}
	}
	for _, g := range good {
		if strings.Contains(desc, g) {
			score += 3
		}
	}
	return score
}

func DefaultInterface() string {
	devs, err := pcap.FindAllDevs()
	if err != nil || len(devs) == 0 {
		return ""
	}

	// сначала попробуем выбрать лучший по «оценке»
	bestName := ""
	bestScore := -1 << 30 // очень маленькое число

	for _, d := range devs {
		// исключим явный loopback по флагу (когда доступен) или по описанию
		desc := d.Description
		nd := normalize(desc)
		if strings.Contains(nd, "loopback") {
			continue
		}

		// нужен нормальный IPv4
		if _, ok := hasGoodIPv4(d.Addresses); !ok {
			continue
		}

		s := scoreDesc(desc)
		// лёгкая коррекция под ОС
		switch runtime.GOOS {
		case "windows":
			// на винде отдаём чуть больший приоритет ethernet/wifi
			if strings.Contains(nd, "ethernet") || strings.Contains(nd, "wi-fi") || strings.Contains(nd, "wifi") || strings.Contains(nd, "беспровод") {
				s += 2
			}
		case "darwin":
			if d.Name == "en0" {
				s += 2
			}
		case "linux":
			if d.Name == "wlan0" || d.Name == "eth0" {
				s += 1
			}
		}

		if s > bestScore {
			bestScore = s
			bestName = d.Name
		}
	}

	if bestName != "" {
		return bestName
	}

	// если ничего «идеального» не нашлось — берём первый non-loopback с IPv4
	for _, d := range devs {
		if strings.Contains(normalize(d.Description), "loopback") {
			continue
		}
		if _, ok := hasGoodIPv4(d.Addresses); ok {
			return d.Name
		}
	}

	// крайний случай: любой с адресами
	for _, d := range devs {
		if len(d.Addresses) > 0 {
			return d.Name
		}
	}
	return devs[0].Name
}

// Возвращает первый вменяемый IPv4 у указанного pcap-интерфейса.
// Это важно на Windows: pcap-имя ≠ системное имя, и net.InterfaceByName там мимо.
func LocalIPv4FromPcap(iface string) (string, bool) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", false
	}
	for _, d := range devs {
		if d.Name == iface {
			if ip, ok := hasGoodIPv4(d.Addresses); ok {
				return ip, true
			}
			return "", false
		}
	}
	return "", false
}
