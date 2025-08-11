package tui

import (
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/whynot00/tg-ip-sniffer/internal/telegram"
)

func newModelForTest() Model {
	m := NewModel(nil, "192.168.1.10", &telegram.IP{})
	m.tgTable = table.New()
	m.otherTable = table.New()
	return m
}

func TestSplitAndSort(t *testing.T) {
	m := newModelForTest()
	now := time.Now()
	// два IP, разное количество пакетов
	m.perIP = map[string]*ipStat{
		"a": {count: 5, last: now.Add(-10 * time.Second), isTG: false},
		"b": {count: 5, last: now.Add(-5 * time.Second), isTG: false},
		"c": {count: 1, last: now, isTG: true},
	}
	m.ipOrder = []string{"a", "b", "c"}

	tg, other := m.splitAndSortIPs()
	if len(tg) != 1 || tg[0] != "c" {
		t.Fatalf("tg expected [c], got %v", tg)
	}
	if len(other) != 2 || other[0] != "b" || other[1] != "a" {
		t.Fatalf("other order unexpected: %v", other)
	}
}

func TestFilterOther(t *testing.T) {
	m := newModelForTest()
	now := time.Now()
	m.perIP = map[string]*ipStat{
		"a": {count: 1, last: now.Add(-2 * time.Minute)},
		"b": {count: 10, last: now.Add(-30 * time.Second)},
		"c": {count: 2, last: now.Add(-20 * time.Second)},
	}
	in := []string{"a", "b", "c"}

	m.OtherMaxAge = 60 * time.Second
	m.MinPackets = 5

	out := m.filterOther(in)
	// остаётся только b: свежий и >=5 пакетов
	if len(out) != 1 || out[0] != "b" {
		t.Fatalf("expected [b], got %v", out)
	}
}

func TestHumanSince(t *testing.T) {
	now := time.Now()
	if s := humanSince(now); s != "только что" {
		t.Fatalf("want 'только что', got %q", s)
	}
	s := humanSince(now.Add(-125 * time.Second))
	if s != "02:05" {
		t.Fatalf("want 02:05, got %q", s)
	}
}
