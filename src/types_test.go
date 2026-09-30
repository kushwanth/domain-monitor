package main

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"strings"
	"testing"
)

func newTestCheckState() *CheckState {
	return &CheckState{
		RDAP:     make(map[string]RDAPState),
		DNS:      make(map[string]DNSState),
		Email:    make(map[string]EmailState),
		DNSSEC:   make(map[string]DNSSECResult),
		NSHealth: make(map[string]NSHealthResult),
		CAA:      make(map[string]CAAResult),
	}
}

func TestStateConditionJSONOmission(t *testing.T) {
	encoded, err := jsonv2.Marshal(DNSState{Status: StatusOK})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"condition"`) {
		t.Fatalf("zero condition must be omitted: %s", encoded)
	}

	encoded, err = jsonv2.Marshal(DNSState{Status: StatusFailed, Condition: StateCondition{Code: CodeDNSLookupFailed}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"condition"`) {
		t.Fatalf("active condition must be encoded: %s", encoded)
	}
}

func TestAlertPriority_TextFormatting(t *testing.T) {
	p := PriorityHigh
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

func BenchmarkCycleAlertCollection(b *testing.B) {
	state := newTestCheckState()
	domains := make([]DomainConfig, 64)
	for i := range domains {
		domain := fmt.Sprintf("domain%d.example", i)
		domains[i] = DomainConfig{Domain: domain, Name: domain}
		state.RDAP[domain] = RDAPState{Status: StatusWarning, Condition: StateCondition{Code: CodeDNSLookupFailed}}
		state.Email[domain] = EmailState{Status: StatusWarning, Condition: StateCondition{Code: CodeDNSLookupFailed}}
	}
	for _, shared := range []bool{false, true} {
		name := "per_domain_slice"
		if shared {
			name = "shared_cycle_slice"
		}
		b.Run(name, func(b *testing.B) {
			prev := make(map[conditionKey]StateCondition)
			b.ReportAllocs()
			for b.Loop() {
				var alerts []Alert
				for _, domain := range domains {
					if shared {
						alerts = collectDomainAlerts(alerts, state, domain, prev)
					} else {
						alerts = append(alerts, collectDomainAlerts(nil, state, domain, prev)...)
					}
				}
				if len(alerts) != 2*len(domains) {
					b.Fatal("missing alerts")
				}
			}
		})
	}
}
