package ports

import (
	"context"
	"log"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	psnet "github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

// Tracker отслеживает порты процесса с именем appName и
// шлёт уведомления в updateCh при изменении набора портов.
type Tracker struct {
	mu       sync.RWMutex
	appName  string
	ports    []int         // нормализованный (отсортированный, без дублей) набор портов
	updateCh chan struct{} // сигнал "порты изменились"
}

// NewTracker создаёт трекер и делает первичное наполнение портов.
func NewTracker(appName string) *Tracker {
	t := &Tracker{
		appName:  appName,
		updateCh: make(chan struct{}, 1),
	}
	t.refresh()
	return t
}

// Updates возвращает канал с уведомлениями об изменениях портов.
func (t *Tracker) Updates() <-chan struct{} { return t.updateCh }

// Snapshot возвращает копию текущего набора портов.
func (t *Tracker) Snapshot() []int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]int, len(t.ports))
	copy(out, t.ports)
	return out
}

// StartPolling периодически обновляет список портов до отмены контекста.
func (t *Tracker) StartPolling(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.refresh()
		case <-ctx.Done():
			close(t.updateCh)
			return
		}
	}
}

// refresh переcчитывает список портов и, если он изменился, публикует обновление.
func (t *Tracker) refresh() {
	ports := t.collectPorts()

	t.mu.Lock()
	changed := !slices.Equal(ports, t.ports)
	if changed {
		t.ports = ports
	}
	t.mu.Unlock()

	if changed {
		select {
		case t.updateCh <- struct{}{}:
		default: // не блокируем, если сигнал уже висит
		}
	}
}

// collectPorts собирает локальные порты всех соединений процессов с именем t.appName.
func (t *Tracker) collectPorts() []int {
	// 1) Собираем PID'ы по имени — дешевле, чем дергать process.Name() на каждое соединение.
	pids, err := pidsByName(t.appName)
	if err != nil {
		// не фейлимся — просто лог и пустой список
		log.Printf("ports: pidsByName(%q) error: %v", t.appName, err)
		return nil
	}
	if len(pids) == 0 {
		return nil
	}

	// 2) Берём все соединения и фильтруем по нашим PID'ам.
	conns, err := psnet.Connections("all")
	if err != nil {
		log.Printf("ports: connections error: %v", err)
		return nil
	}

	raw := make([]int, 0, len(conns))
	for _, c := range conns {
		if _, ok := pids[c.Pid]; !ok {
			continue
		}
		// интересны только валидные локальные порты
		if c.Laddr.Port > 0 {
			raw = append(raw, int(c.Laddr.Port))
		}
	}

	return normalizePorts(raw)
}

// pidsByName возвращает множество PID'ов процессов с данным именем.
func pidsByName(name string) (map[int32]struct{}, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}
	out := make(map[int32]struct{}, len(procs))
	for _, p := range procs {
		n, err := p.Name()
		if err != nil || n == "" {
			continue
		}
		if n == name {
			out[p.Pid] = struct{}{}
		}
	}
	return out, nil
}

// normalizePorts выкидывает нули/дубли и сортирует возрастающе.
func normalizePorts(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	set := make(map[int]struct{}, len(in))
	for _, p := range in {
		if p > 0 {
			set[p] = struct{}{}
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// intsToStrings пригодится для логов/отладки.
func intsToStrings(v []int) []string {
	out := make([]string, len(v))
	for i, n := range v {
		out[i] = strconv.Itoa(n)
	}
	return out
}
