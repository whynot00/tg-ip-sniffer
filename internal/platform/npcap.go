package platform

import (
	"errors"
	"runtime"

	"github.com/google/gopacket/pcap"
)

// CheckNpcap возвращает nil, если на Windows доступен Npcap (libpcap-API работает).
// На других ОС всегда nil.
func CheckNpcap() error {
	if runtime.GOOS != "windows" {
		return nil
	}
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return errors.New("Npcap не найден или недоступен")
	}
	if len(devs) == 0 {
		return errors.New("Npcap установлен, но интерфейсы не обнаружены")
	}
	return nil
}
