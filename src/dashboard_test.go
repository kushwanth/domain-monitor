package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDashboardBrowserRegressions(t *testing.T) {
	browser, err := exec.LookPath("chromium")
	if err != nil {
		t.Skip("Chromium is required for dashboard regression")
	}
	harness := `
    (async () => {
      const failures = [];
      const expect = (value, message) => { if (!value) failures.push(message); };
      try {
        appState = {
          last_updated: '2026-09-28T00:00:00Z',
          rdap_checks: {
            'example.com': {status:'ok', nameservers:['ns.example.com'], renewal_price:12, expiration:new Date(Date.now() + 20*86400000).toISOString()},
            'custom.example.com': {status:'ok', nameservers:['ns.custom.example.com'], renewal_price:8, expiration:new Date(Date.now() + 400*86400000).toISOString()},
            'unused.example': {status:'skipped', unused:true},
            'letgo.example': {status:'ok', nameservers:['ns.letgo.example'], renewal_price:5, expiration:new Date(Date.now() + 10*86400000).toISOString()},
            'pending.example': {status:'pending'}
          },
          caa_checks: {'example.com': {status:'mismatch', valid:false, issue:['unexpected.example']}},
          email_checks: {
            'example.com': {status:'ok', provider:'google', mx:['mx.google.example'], spf:true, dmarc:true},
            'custom.example.com': {status:'ok', mx:['mail.custom.example.com'], spf:true, dmarc:true}
          },
          dnssec_checks: {'example.com': {source:'doh', valid:true, ds_matches_dnskey:true, rrsig_valid:true, chain_intact:true, algorithms:['ED25519']}},
          ns_health: {'example.com': {status:'ok', valid:true, primary:'ns1.example.com', servers:[
            {nameserver:'ns1.example.com',is_primary:true},{nameserver:'ns2.example.com',is_primary:true},{nameserver:'ns3.example.com',is_primary:false}
          ]}},
          dns_checks: {
            web: {hostname:'example.com', name:'web', type:'A', status:'ok', expected:['192.0.2.1'], found:['192.0.2.1']},
            bad: {hostname:'example.com', name:'bad', type:'A', status:'mismatch', expected:['192.0.2.2'], found:['192.0.2.3']},
            waiting: {hostname:'example.com', name:'waiting', type:'A', status:'pending'}
          }
        };
        renderDomains();
        updateRenewalPricing();
        updateHeaderTimestamps();
        const domainCard = document.querySelector('#view-domains details[data-search="example.com"]');
        expect(domainCard && document.getElementById('total-renewal-cost').textContent === '25.00', 'Annual minimum renewal cost is wrong');
        expect(document.getElementById('next-year-renewal-cost').textContent === '17.00', 'Next-year renewal cost is wrong');
        const groupName = card => card?.closest('.domain-group')?.querySelector('h2')?.textContent;
        expect(document.querySelectorAll('#view-domains .domain-group').length === 3, 'Dashboard does not show all three domain sections');
        expect(groupName(document.querySelector('#view-domains details[data-search="custom.example.com"]')) === 'Healthy Domains', 'Healthy domain is in the wrong section');
        expect(groupName(domainCard) === 'Domains with Issues', 'Issue domain is in the wrong section');
        expect(groupName(document.querySelector('#view-domains [data-search="unused.example"]')) === 'Unused Domains', 'Unused domain is in the wrong section');
        expect(!document.querySelector('#view-domains details[data-search="unused.example"]'), 'Unused domain should not show check details');
        expect(groupName(document.querySelector('#view-domains details[data-search="letgo.example"]')) === 'Healthy Domains', 'Healthy domain is in the wrong section');
        expect(!document.querySelector('#view-domains details[data-search="pending.example"]'), 'Pending domain is shown before checks finish');
        expect(Array.from(document.querySelectorAll('#view-stats .stat-value')).map(el => el.textContent.trim()).join(',') === '4,2,1,1', 'Domain section counts do not exclude pending checks or keep unused separate');
        expect(domainCard.querySelector('summary .domain-expiry')?.textContent === '20d left', 'Closed domain card does not show days to expiry');
        expect(!document.querySelector('.badge'), 'Badge markup remains visible');
        toggleFilter('healthy');
        expect(document.querySelectorAll('#view-domains .domain-group').length === 1, 'Empty domain sections remain visible');
        toggleFilter('healthy');
        expect(document.querySelector('.sidebar') && document.querySelector('.theme-toggle'), 'Old sidebar controls missing');
        const mobile = matchMedia('(max-width: 768px)').matches;
        const bodyOverflow = getComputedStyle(document.body).overflowY;
        const mainOverflow = getComputedStyle(document.querySelector('.main')).overflowY;
        expect(mobile ? bodyOverflow === 'visible' && mainOverflow === 'visible' : bodyOverflow === 'hidden' && mainOverflow === 'auto', 'Responsive scrolling layout changed');
        const visibleDomainCard = document.querySelector('#view-domains details[data-search="example.com"]');
        visibleDomainCard.querySelector('summary').click();
        expect(visibleDomainCard.open && visibleDomainCard.querySelector('.domain-details').getClientRects().length, 'Domain details do not open in one click');
        expect(visibleDomainCard.textContent.includes('Nameservers'), 'Domain evidence missing');
        const panel = (card, heading) => Array.from(card.querySelectorAll('.detail-panel')).find(p => p.querySelector('h3')?.textContent === heading);
        const providerPanel = panel(visibleDomainCard, 'Email Security');
        expect(providerPanel.textContent.includes('Provider:') && providerPanel.textContent.includes('Google') && !providerPanel.textContent.includes('MX Records:'), 'Configured provider still shows MX hosts');
        const customCard = document.querySelector('#view-domains details[data-search="custom.example.com"]');
        const customEmail = panel(customCard, 'Email Security');
        expect(customEmail.textContent.includes('MX Records:') && customEmail.textContent.includes('mail.custom.example.com') && !customEmail.textContent.includes('Provider:'), 'Custom mail setup does not show MX hosts');
        expect(!panel(visibleDomainCard, 'DNSSEC Validation').textContent.includes('Algorithms:'), 'DNSSEC algorithms are still shown');
        expect(panel(visibleDomainCard, 'Nameserver Health').textContent.includes('Configured NS checked:') && panel(visibleDomainCard, 'Nameserver Health').textContent.includes('3'), 'Nameserver count does not cover all configured servers');
        const previousTheme = document.documentElement.getAttribute('data-theme');
        toggleTheme();
        expect(document.documentElement.getAttribute('data-theme') !== previousTheme, 'Theme toggle fails without storage');
        toggleTheme();

        switchView('dns');
        const dnsCard = document.querySelector('#view-dns details[data-search-id="web"]');
        expect(dnsCard && !document.getElementById('view-dns').classList.contains('hidden'), 'DNS view missing');
        expect(document.querySelectorAll('#view-dns .domain-group').length === 2, 'DNS results are not split by match status');
        expect(groupName(dnsCard) === 'Matched DNS Records', 'Matched DNS record is in the wrong section');
        expect(groupName(document.querySelector('#view-dns details[data-search-id="bad"]')) === 'DNS Records Not Matched', 'Unmatched DNS record is in the wrong section');
        expect(!document.querySelector('#view-dns details[data-search-id="waiting"]'), 'Pending DNS record is visible');
        expect(Array.from(document.querySelectorAll('#view-stats .stat-value')).map(el => el.textContent.trim()).join(',') === '2,1,1', 'DNS match counts are wrong');
        expect(!dnsCard.querySelector('summary').textContent.includes('example.com') && !dnsCard.querySelector('.domain-title .badge'), 'Closed DNS card still shows hostname or type');
        dnsCard.querySelector('summary').click();
        expect(dnsCard.open && dnsCard.textContent.includes('192.0.2.1') && dnsCard.querySelector('.domain-details').textContent.includes('example.com'), 'DNS evidence does not open in one click');
        handleSearch('missing', true);
        expect(!document.querySelector('#view-dns details.domain-card'), 'Search does not filter DNS records');
        clearSearch();
        expect(document.querySelector('#view-dns details.domain-card'), 'Clear search does not restore DNS records');

        const previousState = appState;
        stateETag = '"unchanged"';
        window.fetch = async (_url, options) => {
          expect(options.headers['If-None-Match'] === stateETag, 'Conditional poll omitted the ETag');
          return {status:304, ok:false, json:async()=>{throw new Error('304 body parsed');}};
        };
        window.setTimeout = () => 0;
        await pollState();
        expect(!connectionError && appState === previousState, 'Unchanged poll replaced state');
        window.fetch = async () => { throw new Error('Offline'); };
        await pollState();
        expect(connectionError && appState === previousState && document.getElementById('last-updated').textContent.includes('Connection lost'), 'Offline polling loses the last state');
        document.body.setAttribute('data-audit-result', failures.length ? failures.join(' | ') : 'passed');
      } catch (error) { document.body.setAttribute('data-audit-result', String(error)); }
    })();`
	for _, viewport := range []string{"1440,1000", "768,1024", "500,844"} {
		t.Run(viewport, func(t *testing.T) {
			pageHTML := strings.Replace(string(indexHTML), "    initialize();", harness, 1)
			pageHTML = strings.Replace(pageHTML, "<script>", `<script>Object.defineProperty(window, 'localStorage', {get() {throw new Error('Storage unavailable');}});</script><script>`, 1)
			page := filepath.Join(t.TempDir(), "dashboard.html")
			require.NoError(t, os.WriteFile(page, []byte(pageHTML), 0600))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, browser, "--headless", "--user-data-dir="+t.TempDir(), "--no-sandbox", "--disable-gpu", "--disable-background-networking", "--window-size="+viewport, "--virtual-time-budget=1000", "--dump-dom", "file://"+page+"?theme=dark").Output()
			require.NoError(t, err)
			_, body, found := strings.Cut(string(output), "<body")
			require.True(t, found)
			require.Contains(t, strings.SplitN(body, ">", 2)[0], `data-audit-result="passed"`)
		})
	}
}

func TestDashboardInitialPollingViews(t *testing.T) {
	browser, err := exec.LookPath("chromium")
	if err != nil {
		t.Skip("Chromium is required for dashboard regression")
	}
	state := `{"last_updated":"2026-09-28T00:00:00Z","rdap_checks":{"example.com":{"status":"ok","nameservers":["ns.example.com"],"renewal_price":12}},"dns_checks":{"web:A":{"hostname":"example.com","name":"web","type":"A","status":"ok","expected":["192.0.2.1"],"found":["192.0.2.1"]}}}`
	for _, tc := range []struct {
		name, hash, view, selector string
	}{
		{"domains", "#domains", "domains", "#view-domains details.domain-card"},
		{"dns", "#dns", "dns", "#view-dns details.domain-card"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			harness := fmt.Sprintf(`
    initialize();
    (async () => {
      for (let attempt=0; attempt<50; attempt++) {
        if (appState.last_updated && currentView==='%s' && document.querySelector('%s')) {
          document.body.setAttribute('data-audit-result','passed');
          return;
        }
        await new Promise(resolve=>setTimeout(resolve,20));
      }
      document.body.setAttribute('data-audit-result','Initial polling did not render the selected view');
    })();`, tc.view, tc.selector)
			page := strings.Replace(string(indexHTML), "    initialize();", harness, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/state" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(state))
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(page))
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, browser, "--headless", "--user-data-dir="+t.TempDir(), "--no-sandbox", "--disable-gpu", "--disable-background-networking", "--virtual-time-budget=2000", "--dump-dom", server.URL+tc.hash).Output()
			require.NoError(t, err)
			_, body, found := strings.Cut(string(output), "<body")
			require.True(t, found)
			require.Contains(t, strings.SplitN(body, ">", 2)[0], `data-audit-result="passed"`)
		})
	}
}
