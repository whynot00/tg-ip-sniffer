package filters

import "testing"

func TestBuildPorts_Empty(t *testing.T) {
	if got := BuildPorts(nil); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
	if got := BuildPorts([]int{}); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
}

func TestBuildPorts_Simple(t *testing.T) {
	got := BuildPorts([]int{80})
	want := "(tcp or udp) and (port 80)"
	if got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestBuildPorts_SortAndDedup(t *testing.T) {
	got := BuildPorts([]int{443, 80, 80, 0, -1})
	// порядок должен быть отсортирован и без дублей
	want := "(tcp or udp) and (port 80 or port 443)"
	if got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}
