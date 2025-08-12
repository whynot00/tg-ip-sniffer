package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type mockDumpHandle struct{}

func (m *mockDumpHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, nil
}

func (m *mockDumpHandle) SetBPFFilter(string) error { return nil }
func (m *mockDumpHandle) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (m *mockDumpHandle) Close()                    {}

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
	r.handle = &mockDumpHandle{}

	if err := r.initDumpWriter(); err != nil {
		t.Fatalf("initDumpWriter: %v", err)
	}
	defer func() {
		r.closeDump()
		_ = os.Remove(r.dumpPath)
	}()

	if filepath.Dir(r.dumpPath) != td {
		t.Fatalf("dumpPath %q not in temp dir %q", r.dumpPath, td)
	}
	if _, err := os.Stat(r.dumpPath); err != nil {
		t.Fatalf("dump file not created: %v", err)
	}
}
