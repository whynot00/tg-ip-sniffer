package ports

import (
	"context"
	"slices"
	"strconv"
	"sync"
	"time"

	psnet "github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

type Tracker struct {
	mu       sync.RWMutex
	appName  string
	ports    []int
	updateCh chan struct{}
}

func NewTracker(appName string) *Tracker {
	t := &Tracker{
		appName:  appName,
		updateCh: make(chan struct{}, 1),
	}
	t.listPorts()
	return t
}

func (t *Tracker) Updates() <-chan struct{} { return t.updateCh }

func (t *Tracker) Snapshot() []int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	cp := make([]int, len(t.ports))
	copy(cp, t.ports)
	return cp
}

func (t *Tracker) StartPolling(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.listPorts()
		case <-ctx.Done():
			close(t.updateCh)
			return
		}
	}
}

func (t *Tracker) listPorts() {
	var ports []int

	conns, _ := psnet.Connections("all")
	for _, c := range conns {
		proc, err := process.NewProcess(c.Pid)
		if err != nil {
			continue
		}
		if n, _ := proc.Name(); n == t.appName {
			ports = append(ports, int(c.Laddr.Port))
		}
	}

	t.mu.Lock()
	changed := !slices.Equal(ports, t.ports)
	if changed {
		t.ports = ports
	}
	t.mu.Unlock()

	if changed {
		select {
		case t.updateCh <- struct{}{}:
		default:
		}
	}
}

func intsToStrings(v []int) []string {
	out := make([]string, len(v))
	for i, n := range v {
		out[i] = strconv.Itoa(n)
	}
	return out
}
