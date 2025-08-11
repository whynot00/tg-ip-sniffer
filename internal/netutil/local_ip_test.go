package netutil

import "testing"

func TestLooksLikeNPF(t *testing.T) {
	cases := map[string]bool{
		`\\Device\\NPF_{ABC-123}`: true,
		`\Device\NPF_{GUID}`:      true,
		`Ethernet0`:               false,
		`en0`:                     false,
	}
	for in, want := range cases {
		if got := looksLikeNPF(in); got != want {
			t.Fatalf("looksLikeNPF(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidIPv4(t *testing.T) {
	wantEmpty := [][]byte{
		{127, 0, 0, 1},
		{169, 254, 1, 1},
		{0, 0, 0, 0},
	}
	for _, ip := range wantEmpty {
		if s := validIPv4(ip); s != "" {
			t.Fatalf("expected empty for %v, got %q", ip, s)
		}
	}
	if s := validIPv4([]byte{10, 0, 0, 1}); s == "" {
		t.Fatal("expected non-empty for 10.0.0.1")
	}
}
