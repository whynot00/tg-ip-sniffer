package telegram

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseAndContains_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "# comment")
		fmt.Fprintln(w, "149.154.167.0/24")
		fmt.Fprintln(w, "2001:db8::/32") // IPv6 — пропускаем
		fmt.Fprintln(w, "bad-cidr")      // битая строка — игнорим
	}))
	defer srv.Close()

	// подменяем URL (см. просьбу — сделать cidrURL var)
	old := cidrURL
	cidrURL = srv.URL
	defer func() { cidrURL = old }()

	ip := LoadIP()
	if ip == nil {
		t.Fatal("LoadIP returned nil")
	}
	if !ip.Contains("149.154.167.51") {
		t.Fatal("expected IP to be inside TG subnets")
	}
	if ip.Contains("8.8.8.8") {
		t.Fatal("did not expect 8.8.8.8 to be inside")
	}
}

func TestLoadIP_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	old := cidrURL
	cidrURL = srv.URL
	defer func() { cidrURL = old }()

	ip := LoadIP()
	if ip == nil {
		t.Fatal("LoadIP returned nil")
	}
	if ip.Contains("149.154.167.51") {
		t.Fatal("must be empty set on error")
	}
}
