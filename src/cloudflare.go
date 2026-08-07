package main

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"golang.org/x/net/publicsuffix"
)

type CFClient struct {
	API        *cloudflare.API
	CIDRs      []*net.IPNet
	ZoneCache  map[string]string
	CacheMutex sync.RWMutex
}

func InitCloudflare(ctx context.Context, token string) *CFClient {
	cf := &CFClient{
		ZoneCache: make(map[string]string),
	}

	cf.LoadCIDRs()

	// Auto-refresh CF IPs every 24 hours
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(24 * time.Hour):
				cf.LoadCIDRs()
			}
		}
	}()

	if token != "" {
		cfApi, err := cloudflare.NewWithAPIToken(token)
		if err != nil {
			log.Fatalf("[FATAL] Failed to initialize Cloudflare SDK: %v", err)
		}
		_, verificationErr := cfApi.VerifyAPIToken(context.Background())
		if verificationErr != nil {
			log.Fatalf("[FATAL] SECURITY HALT: Cloudflare Token verification failed: %v", err)
		}
		cf.API = cfApi
	}
	return cf
}

func (cf *CFClient) LoadCIDRs() {
	ranges, err := cloudflare.IPs()
	if err != nil {
		log.Printf("[WARN] Failed to fetch Cloudflare IPs: %v", err)
		return
	}

	var newCIDRs []*net.IPNet
	allCIDRs := append(ranges.IPv4CIDRs, ranges.IPv6CIDRs...)
	for _, cidr := range allCIDRs {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			newCIDRs = append(newCIDRs, ipnet)
		}
	}

	cf.CacheMutex.Lock()
	cf.CIDRs = newCIDRs
	cf.CacheMutex.Unlock()
	log.Printf("[INFO] Fetched %d Cloudflare CIDR blocks", len(newCIDRs))
}

func (cf *CFClient) IsCloudflareIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	cf.CacheMutex.RLock()
	defer cf.CacheMutex.RUnlock()
	for _, cidr := range cf.CIDRs {
		if cidr.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func (cf *CFClient) GetZoneID(hostname string) (string, error) {
	root, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		return "", err
	}

	cf.CacheMutex.RLock()
	if id, exists := cf.ZoneCache[root]; exists {
		cf.CacheMutex.RUnlock()
		return id, nil
	}
	cf.CacheMutex.RUnlock()

	id, err := cf.API.ZoneIDByName(root)
	if err != nil {
		return "", err
	}

	cf.CacheMutex.Lock()
	cf.ZoneCache[root] = id
	cf.CacheMutex.Unlock()
	return id, nil
}

func (cf *CFClient) FetchBackendRecords(hostname, recType string) ([]string, error) {
	zoneID, err := cf.GetZoneID(hostname)
	if err != nil {
		return nil, err
	}

	searchType := recType
	if recType == "IP" {
		searchType = ""
	}

	records, _, err := cf.API.ListDNSRecords(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
		Name: hostname,
		Type: searchType,
	})
	if err != nil {
		return nil, err
	}

	var backends []string
	for _, r := range records {
		if recType == "IP" {
			if r.Type == "A" || r.Type == "AAAA" {
				backends = append(backends, strings.ToLower(r.Content))
			}
		} else if searchType == "" || r.Type == searchType {
			backends = append(backends, strings.ToLower(r.Content))
		}
	}
	return backends, nil
}
