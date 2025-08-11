package telegram

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"time"
)

const (
	cidrURL       = "https://core.telegram.org/resources/cidr.txt"
	httpTimeout   = 5 * time.Second
	userAgentHead = "tg-ip-sniffer/1.0 (+https://example.local)"
)

// IP хранит набор Telegram-подсетей для быстрых проверок принадлежности IP.
type IP struct {
	ipNets []*net.IPNet
}

// LoadIP загружает актуальные подсети Telegram и возвращает структуру для Contains().
// При сетевой ошибке не паникует: логирует и возвращает пустой набор.
func LoadIP() *IP {
	ipNets, err := loadTelegramCIDRs()
	if err != nil {
		log.Printf("telegram: load cidr error: %v", err)
		return &IP{ipNets: nil}
	}
	return &IP{ipNets: ipNets}
}

// Contains проверяет, принадлежит ли ipStr подсетям Telegram.
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

// loadTelegramCIDRs скачивает и парсит список подсетей Telegram (IPv4).
func loadTelegramCIDRs() ([]*net.IPNet, error) {
	req, err := http.NewRequest(http.MethodGet, cidrURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgentHead)

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &httpError{code: resp.StatusCode}
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 4*1024), 1024*1024) // на всякий
	var ipNets []*net.IPNet

	for sc.Scan() {
		line := trim(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		// Пропускаем IPv6 до тех пор, пока не добавим поддержку в остальном коде.
		if hasColon(line) {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			// Линия битая — пропустим, не валим всю загрузку.
			log.Printf("telegram: bad cidr %q: %v", line, err)
			continue
		}
		ipNets = append(ipNets, ipNet)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ipNets, nil
}

// --- мелкие утилиты ниже ---

type httpError struct{ code int }

func (e *httpError) Error() string { return http.StatusText(e.code) }

// trim — быстрый трим без лишних аллокаций для часто пустых строк.
func trim(s string) string {
	// стандартный strings.TrimSpace вполне ок, но Scanner обычно даёт уже без \r\n
	// оставим как есть для лаконичности:
	for len(s) > 0 {
		switch s[0] {
		case ' ', '\t', '\r', '\n':
			s = s[1:]
		default:
			goto tail
		}
	}
tail:
	for len(s) > 0 {
		switch s[len(s)-1] {
		case ' ', '\t', '\r', '\n':
			s = s[:len(s)-1]
		default:
			return s
		}
	}
	return s
}

func hasColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}
