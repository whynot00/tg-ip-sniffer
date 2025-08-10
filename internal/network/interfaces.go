package network

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

type Ports struct {
	mu       *sync.RWMutex
	appName  string
	ports    []string
	updateCh chan struct{}
}

func LoadPorts(appName string) *Ports {

	p := &Ports{
		mu:       &sync.RWMutex{},
		appName:  appName,
		updateCh: make(chan struct{}, 1),
	}

	p.listPorts()

	return p
}

func (p *Ports) Updates() <-chan struct{} {

	return p.updateCh
}

func (p *Ports) Contains(port string) bool {

	return slices.Contains(p.ports, port)
}

func (p *Ports) Snapshot() []string {

	p.mu.RLock()
	defer p.mu.RUnlock()

	ports := make([]string, len(p.ports))
	copy(ports, p.ports)

	for idx, p := range p.ports {
		ports[idx] = fmt.Sprintf("port %s", p)
	}

	return ports

}

func (p *Ports) StartPooling(ctx context.Context) {

	ticker := time.NewTicker(time.Second * 3)

	for {
		select {
		case <-ticker.C:
			p.listPorts()

		case <-ctx.Done():

			close(p.updateCh)
			return
		}
	}

}

func (p *Ports) listPorts() {
	var ports []string

	connections, _ := net.Connections("all")
	for _, conn := range connections {

		proc, err := process.NewProcess(conn.Pid)
		if err != nil {
			continue
		}

		if n, _ := proc.Name(); n == p.appName {
			ports = append(ports, strconv.Itoa(int(conn.Laddr.Port)))
		}

	}

	p.mu.Lock()
	changed := !slices.Equal(ports, p.ports)

	if changed {
		p.ports = ports
	}
	p.mu.Unlock()

	if changed {

		select {
		// если канал пустой пуляем в него
		case p.updateCh <- struct{}{}:

		// если не пустой то скипаем
		default:
		}

	}

}
