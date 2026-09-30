package main

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"strings"
	"testing"
	"time"
	"unsafe"
)

var benchmarkPublishedState []byte
var benchmarkCycleState *CheckState
var benchmarkWHOISTiers []*DomainTierData

func benchmarkIndexes(length int) []int {
	indexes := make([]int, length)
	for i := range indexes {
		indexes[i] = i
	}
	return indexes
}

func BenchmarkStructFootprint(b *testing.B) {
	for b.Loop() {
	}
	b.ReportMetric(float64(unsafe.Sizeof(AppState{})), "app_state_bytes")
	b.ReportMetric(float64(unsafe.Sizeof(AppConfig{})), "app_config_bytes")
	b.ReportMetric(float64(unsafe.Sizeof(DomainConfig{})), "domain_config_bytes")
	b.ReportMetric(float64(unsafe.Sizeof(DNSTask{})), "dns_task_bytes")
	b.ReportMetric(float64(unsafe.Sizeof(StateCondition{})), "state_condition_bytes")
	b.ReportMetric(float64(unsafe.Sizeof(DNSState{})), "dns_state_bytes")
	b.ReportMetric(float64(unsafe.Sizeof(RDAPState{})), "rdap_state_bytes")
	b.ReportMetric(float64(unsafe.Sizeof(EmailState{})), "email_state_bytes")
	b.ReportMetric(float64(unsafe.Sizeof(DNSSECResult{})), "dnssec_result_bytes")
	b.ReportMetric(float64(unsafe.Sizeof(NSHealthResult{})), "ns_health_result_bytes")
	b.ReportMetric(float64(unsafe.Sizeof(cycleEvidence{})), "cycle_evidence_bytes")
}

func benchmarkStoreDNSResults(state *CheckState, results []DNSResult) {
	for _, result := range results {
		state.storeDNSResultValue(result)
	}
}

// benchmarkCycleFixture holds network results outside the timed region.
func benchmarkCycleFixture(size int) ([]DomainConfig, []RDAPState, []EmailState, []DNSResult) {
	domains := make([]DomainConfig, size)
	rdapResults := make([]RDAPState, size)
	emailResults := make([]EmailState, size)
	dnsResults := make([]DNSResult, size)
	for i := range size {
		domain := fmt.Sprintf("domain-%04d.example", i)
		name := fmt.Sprintf("record-%04d", i)
		domains[i] = DomainConfig{Domain: domain, Name: domain, CheckEmailSecurity: true}
		rdapResults[i] = RDAPState{
			Status: StatusOK, Registrar: "Example Registrar", Expiration: "2027-09-28T00:00:00Z",
			Nameservers: []string{"ns1.example", "ns2.example"},
		}
		emailResults[i] = EmailState{Status: StatusOK, MX: []string{"mail.example"}}
		dnsResults[i] = DNSResult{Name: name, State: DNSState{
			Hostname: domain, Name: name, Type: RecordTypeTXT, Status: StatusOK,
			Expected: []string{"v=spf1 include:example.net -all"},
			Found:    []string{"v=spf1 include:example.net -all"},
		}}
	}
	return domains, rdapResults, emailResults, dnsResults
}

// BenchmarkCycleAssemblyAndPublication measures the current cycle ownership path.
func BenchmarkCycleAssemblyAndPublication(b *testing.B) {
	for _, size := range []int{100, 1000} {
		domains, rdapResults, emailResults, dnsResults := benchmarkCycleFixture(size)
		dnsTasks := make([]DNSTask, size)
		for i := range dnsTasks {
			dnsTasks[i].Name = dnsResults[i].Name
		}
		cfg := AppConfig{Domains: domains, DNSRecords: dnsTasks}
		active := activeChecks{domains: benchmarkIndexes(size), dnsRecords: benchmarkIndexes(size)}
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			app := NewAppState(AppConfig{})
			b.ReportAllocs()
			for b.Loop() {
				state := newCycleState(cfg, active)
				benchmarkStoreDNSResults(state, dnsResults)
				for index, domain := range domains {
					state.RDAP[domain.Domain] = rdapResults[index]
					state.Email[domain.Domain] = emailResults[index]
				}
				publishCycleState(app, state, time.Hour)
				benchmarkCycleState = state
			}
			if encoded, ok := app.PublishedJSON(); ok {
				benchmarkPublishedState = encoded
				b.ReportMetric(float64(len(encoded)), "json_bytes")
			}
		})
	}
}

func BenchmarkDNSContainsMatching(b *testing.B) {
	found := make([]string, 8)
	expected := make([]string, 8)
	for i := range found {
		found[i] = fmt.Sprintf("selector-%d.%s", i, strings.Repeat("MiXeD", 16))
		expected[i] = fmt.Sprintf("selector-%d.%s", i, strings.Repeat("mixed", 16))
	}
	task := DNSTask{MatchType: MatchContains, Expected: expected}
	b.ReportAllocs()
	for b.Loop() {
		if valid, _, _ := validateRecordsWithReason(task, found); !valid {
			b.Fatal("expected all records to match")
		}
	}
}

func BenchmarkPublicationEncoding(b *testing.B) {
	domains, rdapResults, emailResults, dnsResults := benchmarkCycleFixture(1000)
	dnsTasks := make([]DNSTask, len(dnsResults))
	for i := range dnsTasks {
		dnsTasks[i].Name = dnsResults[i].Name
	}
	state := newCycleState(AppConfig{Domains: domains, DNSRecords: dnsTasks}, activeChecks{
		domains: benchmarkIndexes(len(domains)), dnsRecords: benchmarkIndexes(len(dnsTasks)),
	})
	benchmarkStoreDNSResults(state, dnsResults)
	for index, domain := range domains {
		state.RDAP[domain.Domain] = rdapResults[index]
		state.Email[domain.Domain] = emailResults[index]
	}
	b.ReportAllocs()
	for b.Loop() {
		encoded, err := jsonv2.Marshal(state)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkPublishedState = encoded
	}
}

func BenchmarkWHOISTierRetention(b *testing.B) {
	template := "Domain Name: EXAMPLE.COM\nRegistry Expiry Date: 2030-08-13T04:00:00Z\nRegistrar: Example Registrar\nName Server: ns1.example.com\n" + strings.Repeat("padding\n", 32_000)
	benchmarkWHOISTiers = make([]*DomainTierData, 0, b.N)
	b.ReportAllocs()
	for b.Loop() {
		raw := strings.Clone(template)
		benchmarkWHOISTiers = append(benchmarkWHOISTiers, extractWHOISTier(raw, SourceWHOIS, "whois.example"))
	}
}
