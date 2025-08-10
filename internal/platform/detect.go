package platform

import (
	"runtime"
	"strings"

	"github.com/google/gopacket/pcap"
)

// TelegramProcessName возвращает имя процесса Telegram под текущей ОС.
func TelegramProcessName() string {
	if runtime.GOOS == "windows" {
		return "Telegram.exe"
	}
	return "Telegram"
}

// DefaultInterface пытается подобрать подходящий интерфейс под текущую ОС.
// Для Windows берёт NPF-устройство с описанием "Wi‑Fi"/"Ethernet", иначе первый не-loopback.
// Для macOS по умолчанию "en0" (если есть), иначе первый не-loopback.
// Для Linux пытается wlan0/eth0, иначе первый не-loopback.
func DefaultInterface() string {
	devs, err := pcap.FindAllDevs()
	if err != nil || len(devs) == 0 {
		return ""
	}

	isLoop := func(desc string) bool {
		desc = strings.ToLower(desc)
		return strings.Contains(desc, "loopback")
	}

	pickFirstNonLoop := func() string {
		for _, d := range devs {
			if !isLoop(d.Description) && len(d.Addresses) > 0 {
				return d.Name
			}
		}
		return ""
	}

	switch runtime.GOOS {
	case "windows":
		// Предпочтения по описанию
		for _, d := range devs {
			ld := strings.ToLower(d.Description)
			if (strings.Contains(ld, "wi-fi") || strings.Contains(ld, "wifi") ||
				strings.Contains(ld, "wireless") || strings.Contains(ld, "ethernet")) &&
				!isLoop(d.Description) && len(d.Addresses) > 0 {
				return d.Name
			}
		}
		return pickFirstNonLoop()

	case "darwin":
		// Поищем именно en0 среди pcap-устройств
		for _, d := range devs {
			if d.Name == "en0" && !isLoop(d.Description) && len(d.Addresses) > 0 {
				return d.Name
			}
		}
		return pickFirstNonLoop()

	case "linux":
		// Попробуем самые частые имена
		prefs := []string{"wlan0", "eth0"}
		for _, p := range prefs {
			for _, d := range devs {
				if d.Name == p && !isLoop(d.Description) && len(d.Addresses) > 0 {
					return d.Name
				}
			}
		}
		return pickFirstNonLoop()
	}

	// На всякий случай — любой нормальный
	return pickFirstNonLoop()
}
