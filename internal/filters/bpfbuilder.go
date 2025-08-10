package filters

import (
	"strconv"
	"strings"
)

// BuildPorts собирает BPF-фильтр по списку портов.
// []int{80,443} -> "(port 80 or port 443)"
func BuildPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = "port " + strconv.Itoa(p)
	}
	return "(" + strings.Join(parts, " or ") + ")"
}
