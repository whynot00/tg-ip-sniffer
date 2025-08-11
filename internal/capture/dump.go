package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket/pcapgo"
)

func defaultDumpPath() string {
	ts := time.Now().Format("20060102-150405")
	_ = os.MkdirAll("captures", 0o755)
	return filepath.Join("captures", fmt.Sprintf("tg-%s.pcap", ts))
}

func (r *NetworkReader) EnableDump(path string) {
	r.dumpEnabled = true
	r.dumpPath = path
}

func (r *NetworkReader) mustInitDumpWriter() error {
	if !r.dumpEnabled || r.handle == nil {
		return nil
	}
	if r.dumpPath == "" {
		r.dumpPath = defaultDumpPath()
	}
	f, err := os.Create(r.dumpPath)
	if err != nil {
		return err
	}
	r.dumpFile = f

	w := pcapgo.NewWriter(f)
	// фиксированный snaplen = 1600, link type берём из handle
	if err := w.WriteFileHeader(1600, r.handle.LinkType()); err != nil {
		_ = f.Close()
		r.dumpFile = nil
		return err
	}
	r.dumpWriter = w
	return nil
}

func (r *NetworkReader) closeDump() {
	if r.dumpFile != nil {
		_ = r.dumpFile.Sync()
		_ = r.dumpFile.Close()
		r.dumpFile = nil
	}
	r.dumpWriter = nil
}
