package main

import (
	jsonv2 "encoding/json/v2"
	"fmt"
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

func TestCycleStateOwnsWorkerResults(t *testing.T) {
	cond := &StateCondition{Code: CodeDNSLookupFailed, Target: "original"}
	tier := &DomainTierData{Nameservers: []string{"ns.original"}, DomainStatus: []string{"original"}}
	res := DomainResult{
		Domain:   "example.com",
		RDAP:     RDAPState{Status: StatusFailed, Condition: cond, Nameservers: []string{"ns.original"}, DomainStatus: []string{"original"}, Discrepancies: []string{"original"}, RegistryTier: tier, RegistrarTier: tier},
		Email:    EmailState{Status: StatusFailed, Condition: cond, MX: []string{"mx.original"}, DKIMValid: []string{"original"}},
		DNSSEC:   DNSSECResult{Valid: true, Condition: cond, Algorithms: []string{"original"}},
		NSHealth: NSHealthResult{Status: StatusFailed, Condition: cond, Servers: []NSHealthServerResult{{Nameserver: "ns.original"}}},
		CAA:      &CAAResult{Condition: cond, Issue: []string{"original"}, IssueWild: []string{"original"}, IssueMail: []string{"original"}, UnknownCAs: []string{"original"}},
	}
	dns := DNSResult{Name: "record", State: DNSState{Status: StatusFailed, Condition: cond, Expected: []string{"original"}, Found: []string{"original"}}}
	state := NewCheckState()
	state.ApplyDomainResult(res)
	state.ApplyDNSResult(dns)
	before, err := jsonv2.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	cond.Target = "mutated"
	for _, values := range [][]string{tier.Nameservers, tier.DomainStatus, res.RDAP.Nameservers, res.RDAP.DomainStatus, res.RDAP.Discrepancies, res.Email.MX, res.Email.DKIMValid, res.DNSSEC.Algorithms, res.CAA.Issue, res.CAA.IssueWild, res.CAA.IssueMail, res.CAA.UnknownCAs, dns.State.Expected, dns.State.Found} {
		values[0] = "mutated"
	}
	res.NSHealth.Servers[0].Nameserver = "mutated"
	res.CAA.Error = "mutated"
	after, err := jsonv2.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("mutating worker results changed aggregated state")
	}
	state.RDAP[res.Domain].Condition.Target = "cycle mutation"
	state.RDAP[res.Domain].RegistryTier.Nameservers[0] = "cycle mutation"
	if cond.Target != "mutated" || tier.Nameservers[0] != "mutated" {
		t.Fatal("cycle state mutated worker data")
	}
	if state.Email[res.Domain].Condition.Target != "original" {
		t.Fatal("independent check conditions share mutable state")
	}
}

func BenchmarkCycleAlertCollection(b *testing.B) {
	state := NewCheckState()
	domains := make([]DomainConfig, 64)
	for i := range domains {
		domain := fmt.Sprintf("domain%d.example", i)
		domains[i] = DomainConfig{Domain: domain, Name: domain}
		state.RDAP[domain] = RDAPState{Status: StatusWarning, Condition: &StateCondition{Code: CodeDNSLookupFailed}}
		state.Email[domain] = EmailState{Status: StatusWarning, Condition: &StateCondition{Code: CodeDNSLookupFailed}}
	}
	for _, shared := range []bool{false, true} {
		name := "per_domain_slice"
		if shared {
			name = "shared_cycle_slice"
		}
		b.Run(name, func(b *testing.B) {
			prev := make(map[string]StateCondition)
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
