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

// appBaseDir возвращает директорию, где лежит бинарник.
// Если вдруг не удалось — падаем назад на текущую рабочую директорию.
func appBaseDir() string {
	exePath, err := os.Executable()
	if err == nil {
		if real, err2 := filepath.EvalSymlinks(exePath); err2 == nil {
			exePath = real
		}
		return filepath.Dir(exePath)
	}
	wd, _ := os.Getwd()
	return wd
}

// defaultDumpPath -> <папка_бинарника>/captures/tg-YYYYMMDD-HHMMSS.pcap
func defaultDumpPath() string {
	base := appBaseDir()
	dir := filepath.Join(base, defaultDumpDir)
	_ = os.MkdirAll(dir, 0o755)

	ts := time.Now().Format("20060102-150405")
	return filepath.Join(dir, fmt.Sprintf("%s-%s.pcap", defaultDumpPrefix, ts))
}

// absFromAppDir делает путь абсолютным относительно папки бинарника,
// если он не абсолютный.
func absFromAppDir(p string) string {
	if p == "" || p == "." {
		return defaultDumpPath()
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(appBaseDir(), p))
}

// EnableDump включает запись дампа. Только сохраняем настройку.
func (r *NetworkReader) EnableDump(path string) {
	r.dumpEnabled = true
	// не приводим к абсолютному здесь — сделаем это в initDumpWriter,
	// чтобы спокойно обрабатывать "" / "." и директории.
	r.dumpPath = filepath.Clean(path)
}

// initDumpWriter создаёт pcap‑writer после успешного OpenLive.
func (r *NetworkReader) initDumpWriter() error {
	if !r.dumpEnabled || r.handle == nil {
		return nil
	}

	// Нормализуем базово ("" / ".")
	if r.dumpPath == "" || r.dumpPath == "." {
		r.dumpPath = defaultDumpPath()
	} else {
		// Превращаем в абсолютный относительно папки бинарника
		r.dumpPath = absFromAppDir(r.dumpPath)

		st, err := os.Stat(r.dumpPath)
		switch {
		case err == nil && st.IsDir():
			// это существующая директория — создаём имя файла внутри
			filename := fmt.Sprintf("%s-%s.pcap", defaultDumpPrefix, time.Now().Format("20060102-150405"))
			r.dumpPath = filepath.Join(r.dumpPath, filename)

		case os.IsNotExist(err) && filepath.Ext(r.dumpPath) == "":
			// не существует и без расширения → трактуем как директорию
			if mkErr := os.MkdirAll(r.dumpPath, 0o755); mkErr != nil {
				return fmt.Errorf("mkdumpdir: %w", mkErr)
			}
			filename := fmt.Sprintf("%s-%s.pcap", defaultDumpPrefix, time.Now().Format("20060102-150405"))
			r.dumpPath = filepath.Join(r.dumpPath, filename)

		default:
			// считаем файлом — гарантируем родительскую директорию
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

// closeDump закрывает файл дампа.
func (r *NetworkReader) closeDump() {
	if r.dumpFile != nil {
		_ = r.dumpFile.Sync()
		_ = r.dumpFile.Close()
		r.dumpFile = nil
	}
	r.dumpWriter = nil
}
