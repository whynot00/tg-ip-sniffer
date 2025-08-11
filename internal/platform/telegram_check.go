package platform

import (
	"time"

	"github.com/shirou/gopsutil/process"
)

func IsProcessRunning(name string) bool {
	procs, _ := process.Processes()
	for _, p := range procs {
		n, _ := p.Name()
		if n == name {
			return true
		}
	}
	return false
}

// WaitForProcess ждёт появления процесса name не дольше timeout.
// Возвращает true, если процесс появился.
func WaitForProcess(name string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for {
		if IsProcessRunning(name) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		<-tick.C
	}
}
