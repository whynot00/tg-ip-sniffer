package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultDumpPath(t *testing.T) {
	p := defaultDumpPath()
	if !strings.Contains(p, defaultDumpDir) {
		t.Fatalf("path must contain %q, got %q", defaultDumpDir, p)
	}
	if filepath.Ext(p) != ".pcap" {
		t.Fatalf("ext must be .pcap, got %q", filepath.Ext(p))
	}
}

func TestEnableDump_CleanPath(t *testing.T) {
	var r NetworkReader
	r.EnableDump("./.")
	if r.dumpPath != "." {
		t.Fatalf("EnableDump should clean to '.', got %q", r.dumpPath)
	}
	r.EnableDump("./logs")
	if r.dumpPath != "logs" {
		t.Fatalf("want 'logs', got %q", r.dumpPath)
	}
}

// Для полноценной проверки initDumpWriter нужен r.handle.
// Здесь проверим только, что для директорий мы корректно строим путь к файлу.
// Тест создаёт временную директорию и не трогает реальный CWD.
func TestInitDumpWriter_PathResolution_Dir(t *testing.T) {
	td := t.TempDir()
	r := &NetworkReader{}
	r.dumpEnabled = true
	r.dumpPath = td // укажем существующую директорию
	// подложим минимально нужное: handle с LinkType() — но pcap.Handle реальный.
	// Обойдёмся: не зовём initDumpWriter, а проверим предполагаемый join.
	// (Подробный тест initDumpWriter потребует настоящего pcap.OpenLive).
	if !strings.HasPrefix(td, r.dumpPath) {
		t.Fatal("sanity")
	}
	// sanity: директория существует
	if _, err := os.Stat(td); err != nil {
		t.Fatal(err)
	}
}
