package main

import (
	"testing"
)

func TestAlertPriority_TextFormatting(t *testing.T) {
	var p AlertPriority = PriorityHigh
	b, err := p.MarshalText()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(b) != "high" {
		t.Errorf("expected 'high', got %s", b)
	}

	var p2 AlertPriority
	err = p2.UnmarshalText([]byte("urgent"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p2 != PriorityUrgent {
		t.Errorf("expected PriorityUrgent, got %v", p2)
	}

	err = p2.UnmarshalText([]byte("invalid"))
	if err == nil {
		t.Error("expected error for invalid unmarshal text")
	}

	var invalidP AlertPriority = 99
	_, err = invalidP.MarshalText()
	if err == nil {
		t.Error("expected error for invalid marshal text")
	}
}
