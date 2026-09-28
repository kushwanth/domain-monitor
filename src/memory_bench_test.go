package main

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

var benchmarkPublishedState []byte
var benchmarkCycleState *CheckState
var benchmarkWHOISTiers []*DomainTierData
var benchmarkWHOISRaw []string
var benchmarkWideDomains []DomainConfig
var benchmarkWideTasks []DNSTask
var benchmarkDomainRefs []*DomainConfig
var benchmarkTaskRefs []*DNSTask
var benchmarkDomainIndexes []int
var benchmarkTaskIndexes []int

func benchmarkPointers[T any](items []T) []*T {
	pointers := make([]*T, len(items))
	for i := range items {
		pointers[i] = &items[i]
	}
	return pointers
}

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
}

func benchmarkStoreDNSResults(state *CheckState, results []DNSResult, copyInput bool) {
	for _, result := range results {
		if copyInput {
			state.ApplyDNSResult(result)
		} else {
			storeDNSResult(state, result)
		}
	}
}

// benchmarkCycleFixture holds network results outside the timed region. Its
// slices and pointers are treated as immutable by both assembly paths.
func benchmarkCycleFixture(size int) ([]DomainConfig, []DomainResult, []DNSResult) {
	domains := make([]DomainConfig, size)
	domainResults := make([]DomainResult, size)
	dnsResults := make([]DNSResult, size)
	for i := range size {
		domain := fmt.Sprintf("domain-%04d.example", i)
		name := fmt.Sprintf("record-%04d", i)
		domains[i] = DomainConfig{Domain: domain, Name: domain, CheckEmailSecurity: true}
		domainResults[i] = DomainResult{
			Domain: domain,
			RDAP: RDAPState{
				Status: StatusOK, Registrar: "Example Registrar", Expiration: "2027-09-28T00:00:00Z",
				Nameservers: []string{"ns1.example", "ns2.example"},
			},
			Email: EmailState{Status: StatusOK, MX: []string{"mail.example"}},
		}
		dnsResults[i] = DNSResult{Name: name, State: DNSState{
			Hostname: domain, Name: name, Type: RecordTypeTXT, Status: StatusOK,
			Expected: []string{"v=spf1 include:example.net -all"},
			Found:    []string{"v=spf1 include:example.net -all"},
		}}
	}
	return domains, domainResults, dnsResults
}

func BenchmarkActiveConfigViews(b *testing.B) {
	domains := make([]DomainConfig, 1000)
	tasks := make([]DNSTask, 1000)
	b.Run("wide_copies", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			activeDomains := make([]DomainConfig, 0, len(domains))
			activeTasks := make([]DNSTask, 0, len(tasks))
			for _, domain := range domains {
				activeDomains = append(activeDomains, domain)
			}
			for _, task := range tasks {
				activeTasks = append(activeTasks, task)
			}
			benchmarkWideDomains, benchmarkWideTasks = activeDomains, activeTasks
		}
	})
	b.Run("owned_pointers", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			benchmarkDomainRefs = benchmarkPointers(domains)
			benchmarkTaskRefs = benchmarkPointers(tasks)
		}
	})
	b.Run("owned_indices", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			benchmarkDomainIndexes = benchmarkIndexes(len(domains))
			benchmarkTaskIndexes = benchmarkIndexes(len(tasks))
		}
	})
}

// BenchmarkCycleAssemblyAndPublication isolates the in-memory cycle boundary.
// The defensive variant is the former cycle assembly behavior, while owned is
// the current internal transfer path. Both publish the same keyed JSON schema.
func BenchmarkCycleAssemblyAndPublication(b *testing.B) {
	for _, size := range []int{100, 1000} {
		domains, domainResults, dnsResults := benchmarkCycleFixture(size)
		dnsTasks := make([]DNSTask, size)
		for i := range dnsTasks {
			dnsTasks[i].Name = dnsResults[i].Name
		}
		cfg := AppConfig{Domains: domains, DNSRecords: dnsTasks}
		active := activeChecks{domains: benchmarkIndexes(size), dnsRecords: benchmarkIndexes(size)}
		for _, owned := range []bool{false, true} {
			name := "defensive_copy"
			if owned {
				name = "owned_transfer"
			}
			b.Run(fmt.Sprintf("%d_%s", size, name), func(b *testing.B) {
				app := NewAppState(AppConfig{})
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					state := prepareCycleStateForWorkload(cfg, active)
					if owned {
						benchmarkStoreDNSResults(state, dnsResults, false)
						for _, result := range domainResults {
							state.takeDomainResult(result)
						}
					} else {
						benchmarkStoreDNSResults(state, dnsResults, true)
						for _, result := range domainResults {
							state.ApplyDomainResult(result)
						}
					}
					publishCycleState(app, state, time.Hour)
				}
				b.StopTimer()
				if encoded, ok := app.PublishedJSON(); ok {
					benchmarkPublishedState = encoded
					b.ReportMetric(float64(len(encoded)), "json_bytes")
				}
			})
		}
	}
}

func BenchmarkResultTransfer(b *testing.B) {
	for _, size := range []int{100, 1000} {
		_, domainResults, dnsResults := benchmarkCycleFixture(size)
		for _, owned := range []bool{false, true} {
			name := "defensive_copy"
			if owned {
				name = "owned_transfer"
			}
			b.Run(fmt.Sprintf("%d_%s", size, name), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					state := &CheckState{
						RDAP: make(map[string]RDAPState, size), DNS: make(map[string]DNSState, size),
						Email: make(map[string]EmailState, size),
					}
					if owned {
						benchmarkStoreDNSResults(state, dnsResults, false)
						for _, result := range domainResults {
							state.takeDomainResult(result)
						}
					} else {
						benchmarkStoreDNSResults(state, dnsResults, true)
						for _, result := range domainResults {
							state.ApplyDomainResult(result)
						}
					}
					benchmarkCycleState = state
				}
			})
		}
	}
}

// BenchmarkWorkerResultStorage compares the former per-task goroutines and
// full-size staging slices with fixed workers writing into cycle maps.
func BenchmarkWorkerResultStorage(b *testing.B) {
	const size = 1000
	_, domainResults, dnsResults := benchmarkCycleFixture(size)
	for _, direct := range []bool{false, true} {
		name := "staged_per_task"
		if direct {
			name = "fixed_workers_direct"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				state := &CheckState{
					RDAP: make(map[string]RDAPState, size), DNS: make(map[string]DNSState, size),
					Email: make(map[string]EmailState, size),
				}
				if direct {
					var mu sync.Mutex
					runBoundedChecks(size*2, func(index int) {
						mu.Lock()
						if index < size {
							state.takeDNSResult(dnsResults[index])
						} else {
							state.takeDomainResult(domainResults[index-size])
						}
						mu.Unlock()
					})
				} else {
					// Acquiring a slot before launching mirrors errgroup.SetLimit.
					dnsStage := make([]DNSResult, size)
					slots := make(chan struct{}, DefaultMaxConcurrency)
					var workers sync.WaitGroup
					for i := range dnsStage {
						slots <- struct{}{}
						workers.Go(func() {
							defer func() { <-slots }()
							dnsStage[i] = dnsResults[i]
						})
					}
					workers.Wait()
					benchmarkStoreDNSResults(state, dnsStage, false)
					domainStage := make([]DomainResult, size)
					for i := range domainStage {
						slots <- struct{}{}
						workers.Go(func() {
							defer func() { <-slots }()
							domainStage[i] = domainResults[i]
						})
					}
					workers.Wait()
					for _, result := range domainStage {
						state.takeDomainResult(result)
					}
				}
				benchmarkCycleState = state
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
	b.Run("legacy_nested_lowercase", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, wanted := range expected {
				matched := false
				for _, actual := range found {
					if strings.Contains(strings.ToLower(actual), strings.ToLower(wanted)) {
						matched = true
						break
					}
				}
				if !matched {
					b.Fatal("expected all records to match")
				}
			}
		}
	})
	b.Run("current_cached_lowercase", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if valid, _, _ := validateRecordsWithReason(task, found); !valid {
				b.Fatal("expected all records to match")
			}
		}
	})
}

func BenchmarkPublicationEncoding(b *testing.B) {
	domains, domainResults, dnsResults := benchmarkCycleFixture(1000)
	dnsTasks := make([]DNSTask, len(dnsResults))
	for i := range dnsTasks {
		dnsTasks[i].Name = dnsResults[i].Name
	}
	state := prepareCycleStateForWorkload(AppConfig{Domains: domains, DNSRecords: dnsTasks}, activeChecks{
		domains: benchmarkIndexes(len(domains)), dnsRecords: benchmarkIndexes(len(dnsTasks)),
	})
	benchmarkStoreDNSResults(state, dnsResults, false)
	for _, result := range domainResults {
		state.takeDomainResult(result)
	}
	initial, err := jsonv2.Marshal(state)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("marshal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			encoded, err := jsonv2.Marshal(state)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkPublishedState = encoded
		}
	})
	b.Run("marshal_write_preallocated", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var output bytes.Buffer
			output.Grow(len(initial))
			if err := jsonv2.MarshalWrite(&output, state); err != nil {
				b.Fatal(err)
			}
			benchmarkPublishedState = output.Bytes()
		}
	})
}

func BenchmarkWHOISTierRetention(b *testing.B) {
	template := "Domain Name: EXAMPLE.COM\nRegistry Expiry Date: 2030-08-13T04:00:00Z\nRegistrar: Example Registrar\nName Server: ns1.example.com\n" + strings.Repeat("padding\n", 32_000)
	for _, keepRaw := range []bool{false, true} {
		name := "current_extracted_tier"
		if keepRaw {
			name = "legacy_raw_retained"
		}
		b.Run(name, func(b *testing.B) {
			benchmarkWHOISTiers = make([]*DomainTierData, 0, b.N)
			benchmarkWHOISRaw = nil
			if keepRaw {
				benchmarkWHOISRaw = make([]string, 0, b.N)
			}
			b.ReportAllocs()
			for b.Loop() {
				raw := strings.Clone(template)
				benchmarkWHOISTiers = append(benchmarkWHOISTiers, extractWHOISTier(raw, SourceWHOIS, "whois.example"))
				if keepRaw {
					benchmarkWHOISRaw = append(benchmarkWHOISRaw, raw)
				}
			}
		})
	}
}
