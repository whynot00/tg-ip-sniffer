package telegram

import (
	"io"
	"net"
	"net/http"
	"strings"
)

type IP struct {
	ipNets []*net.IPNet
}

func LoadIP() *IP {
	ipNets, err := loadTelegramCIDRs()
	if err != nil {
		panic(err)
	}
	return &IP{ipNets: ipNets}
}

func (i *IP) Contains(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, ipNet := range i.ipNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func loadTelegramCIDRs() ([]*net.IPNet, error) {
	resp, err := http.Get("https://core.telegram.org/resources/cidr.txt")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseCIDRs(string(body))
}

func parseCIDRs(data string) ([]*net.IPNet, error) {
	lines := strings.Split(data, "\n")
	var ipNets []*net.IPNet
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, ":") {
			continue // скипаем IPv6 пока логика не меняется
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			return nil, err
		}
		ipNets = append(ipNets, ipNet)
	}
	return ipNets, nil
}
