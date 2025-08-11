package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket/pcapgo"
)

const (
	defaultDumpDir    = "captures"
	defaultDumpPrefix = "tg"
	defaultSnapLen    = 1600
)

// defaultDumpPath формирует путь вида:
//
//	./captures/tg-YYYYMMDD-HHMMSS.pcap
func defaultDumpPath() string {
	ts := time.Now().Format("20060102-150405")
	_ = os.MkdirAll(defaultDumpDir, 0o755)
	return filepath.Join(defaultDumpDir, fmt.Sprintf("%s-%s.pcap", defaultDumpPrefix, ts))
}

// EnableDump включает запись дампа. Путь может быть пустым/"."
// — тогда будет выбран путь по умолчанию.
func (r *NetworkReader) EnableDump(path string) {
	// не делаем I/O здесь — только сохраняем пожелание
	r.dumpEnabled = true
	r.dumpPath = filepath.Clean(path)
}

// initDumpWriter создаёт pcap‑writer после успешного OpenLive.
// Если указан путь к директории — создаст файл внутри неё.
// Если путь пустой/"." — будет выбран путь по умолчанию.
func (r *NetworkReader) initDumpWriter() error {
	if !r.dumpEnabled || r.handle == nil {
		return nil
	}

	switch r.dumpPath {
	case "", ".":
		r.dumpPath = defaultDumpPath()
	default:
		if st, err := os.Stat(r.dumpPath); err == nil && st.IsDir() {
			// указана директория — кладём файл внутрь
			filename := fmt.Sprintf("%s-%s.pcap", defaultDumpPrefix, time.Now().Format("20060102-150405"))
			r.dumpPath = filepath.Join(r.dumpPath, filename)
		} else {
			// указан файл — гарантируем наличие родительской директории
			if err := os.MkdirAll(filepath.Dir(r.dumpPath), 0o755); err != nil {
				return fmt.Errorf("mkdumpdir: %w", err)
			}
		}
	}

	f, err := os.Create(r.dumpPath)
	if err != nil {
		return fmt.Errorf("create dump file: %w", err)
	}
	r.dumpFile = f

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(uint32(defaultSnapLen), r.handle.LinkType()); err != nil {
		_ = f.Close()
		r.dumpFile = nil
		return fmt.Errorf("write pcap header: %w", err)
	}
	r.dumpWriter = w
	return nil
}

// closeDump корректно закрывает файл дампа.
func (r *NetworkReader) closeDump() {
	if r.dumpFile != nil {
		_ = r.dumpFile.Sync()
		_ = r.dumpFile.Close()
		r.dumpFile = nil
	}
	r.dumpWriter = nil
}
