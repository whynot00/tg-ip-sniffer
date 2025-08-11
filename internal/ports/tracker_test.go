package ports

import "testing"

func TestNormalizePorts(t *testing.T) {
	in := []int{0, 443, 80, 443, -1}
	out := normalizePorts(in)
	if len(out) != 2 || out[0] != 80 || out[1] != 443 {
		t.Fatalf("unexpected normalizePorts result: %v", out)
	}
}

func TestIntsToStrings(t *testing.T) {
	in := []int{1, 20, 300}
	out := intsToStrings(in)
	if len(out) != 3 || out[0] != "1" || out[1] != "20" || out[2] != "300" {
		t.Fatalf("unexpected intsToStrings: %v", out)
	}
}
