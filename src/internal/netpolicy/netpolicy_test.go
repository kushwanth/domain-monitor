package netpolicy

import (
	"net"
	"testing"
)

func TestRestrictedIP(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "224.0.0.1", "::1"} {
		if !RestrictedIP(net.ParseIP(raw)) {
			t.Fatalf("%s must be restricted", raw)
		}
	}
	if RestrictedIP(net.ParseIP("93.184.216.34")) {
		t.Fatal("public address must remain allowed")
	}
}

func TestSanitizeURL(t *testing.T) {
	got := SanitizeURL("https://user:secret@example.com/path?token=secret#fragment")
	if got != "https://example.com/path" {
		t.Fatalf("sanitized URL = %q", got)
	}
	if SanitizeURL("://bad") != "[invalid URL]" {
		t.Fatal("invalid URL must not be echoed")
	}
}
