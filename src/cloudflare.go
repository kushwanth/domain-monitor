package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
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

func InitCloudflare(token string) *CFClient {
	cf := &CFClient{
		ZoneCache: make(map[string]string),
	}

	cf.LoadCIDRs()

	// Auto-refresh CF IPs every 24 hours
	go func() {
		for {
			time.Sleep(24 * time.Hour)
			cf.LoadCIDRs()
		}
	}()

	if token != "" {
		api, err := cloudflare.NewWithAPIToken(token)
		if err != nil {
			log.Fatalf("[FATAL] Failed to initialize Cloudflare SDK: %v", err)
		}
		cf.API = api
		tokenObj, err := cf.API.VerifyAPIToken(context.Background())
		if err != nil {
			log.Fatalf("[FATAL] SECURITY HALT: Cloudflare Token verification failed: %v", err)
		}
		log.Println("[INFO] Cloudflare API Token validated", tokenObj)
	}
	return cf
}

func (cf *CFClient) LoadCIDRsFromReader(r io.Reader) []*net.IPNet {
	var newCIDRs []*net.IPNet
	body, _ := io.ReadAll(r)
	for _, line := range strings.Split(string(body), "\n") {
		if _, ipnet, err := net.ParseCIDR(strings.TrimSpace(line)); err == nil {
			newCIDRs = append(newCIDRs, ipnet)
		}
	}
	return newCIDRs
}

func (cf *CFClient) LoadCIDRs() {
	var newCIDRs []*net.IPNet
	client := &http.Client{Timeout: 10 * time.Second}

	for _, u := range []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		resp, err := client.Do(req)
		if err == nil {
			cidrs := cf.LoadCIDRsFromReader(resp.Body)
			newCIDRs = append(newCIDRs, cidrs...)
			resp.Body.Close()
		}
		cancel()
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
	if recType == "TUNNEL" {
		searchType = "" // Fetch all, we'll manually filter if needed, as API behavior varies for tunnels
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
		if recType == "TUNNEL" {
			// In overhauled Cloudflare API/UI, Tunnel records might show as type "tunnel" or just have the tunnel name in content.
			// Or they might still be CNAMEs pointing to .cfargotunnel.com
			if strings.ToLower(r.Type) == "tunnel" || strings.ToLower(r.Type) == "cname" {
				// Strip .cfargotunnel.com just in case it's exposed as the full CNAME
				content := strings.TrimSuffix(strings.ToLower(r.Content), ".cfargotunnel.com")
				backends = append(backends, content)
			}
		} else if searchType == "" || r.Type == searchType {
			backends = append(backends, strings.ToLower(r.Content))
		}
	}
	return backends, nil
}
