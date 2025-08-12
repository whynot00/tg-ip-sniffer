package filters

import (
	"sort"
	"strconv"
	"strings"
)

const maxPort = 65535

// BuildPorts собирает BPF-фильтр по списку портов.
// Например: []int{443, 80, 80} -> "(tcp or udp) and (port 80 or port 443)".
// Порты сортируются, дубли удаляются и игнорируются значения вне диапазона 1-65535.
func BuildPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	// удаляем дубликаты и сортируем
	uniq := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		if p > 0 && p <= maxPort {
			uniq[p] = struct{}{}
		}
	}
	sorted := make([]int, 0, len(uniq))
	for p := range uniq {
		sorted = append(sorted, p)
	}
	sort.Ints(sorted)

	// собираем строку
	var b strings.Builder
	b.WriteString("(tcp or udp) and (")
	for i, p := range sorted {
		if i > 0 {
			b.WriteString(" or ")
		}
		b.WriteString("port ")
		b.WriteString(strconv.Itoa(p))
	}
	b.WriteByte(')')
	return b.String()
}
