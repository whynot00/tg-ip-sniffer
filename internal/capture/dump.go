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

// EnableDump включает запись дампа. Путь может быть:
//   - пустой или "." → используем путь по умолчанию;
//   - директорией (существующей или новой) → файл создадим внутри неё;
//   - конкретным файлом → создадим именно его.
func (r *NetworkReader) EnableDump(path string) {
	// только сохраняем настройку, без I/O
	r.dumpEnabled = true
	r.dumpPath = filepath.Clean(path)
}

// initDumpWriter создаёт pcap‑writer после успешного OpenLive.
// Логика путей:
//   - "" или "." → defaultDumpPath()
//   - существующая директория → кладём файл внутрь
//   - несуществующий путь без расширения → считаем директорией, создаём и кладём файл внутрь
//   - иначе → считаем файлом, создаём родительскую директорию при необходимости
func (r *NetworkReader) initDumpWriter() error {
	if !r.dumpEnabled || r.handle == nil {
		return nil
	}

	switch r.dumpPath {
	case "", ".":
		r.dumpPath = defaultDumpPath()
	default:
		st, err := os.Stat(r.dumpPath)
		if err == nil && st.IsDir() {
			// уже директория
			filename := fmt.Sprintf("%s-%s.pcap", defaultDumpPrefix, time.Now().Format("20060102-150405"))
			r.dumpPath = filepath.Join(r.dumpPath, filename)
		} else if os.IsNotExist(err) && filepath.Ext(r.dumpPath) == "" {
			// не существует и без расширения → трактуем как директорию
			if mkErr := os.MkdirAll(r.dumpPath, 0o755); mkErr != nil {
				return fmt.Errorf("mkdumpdir: %w", mkErr)
			}
			filename := fmt.Sprintf("%s-%s.pcap", defaultDumpPrefix, time.Now().Format("20060102-150405"))
			r.dumpPath = filepath.Join(r.dumpPath, filename)
		} else {
			// файл: гарантируем наличие родительской директории
			if mkErr := os.MkdirAll(filepath.Dir(r.dumpPath), 0o755); mkErr != nil {
				return fmt.Errorf("mkdumpdir: %w", mkErr)
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
