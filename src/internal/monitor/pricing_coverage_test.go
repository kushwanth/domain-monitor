package monitor

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExtractTLDHandlesEmptyAndMalformedInput(t *testing.T) {
	require.Empty(t, extractTLD(""))
	require.Empty(t, extractTLD("."))
	require.Equal(t, "a.", extractTLD("a.."))
}

func TestPricingExpiredCacheSharesOneConcurrentRefresh(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	manager := NewPricingManager(&MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"tlds":[{"tld":"com","renewal":24}]}`))}, nil
	}})
	old := &pricingCatalog{prices: map[string]float64{"com": 12}, fetchedAt: time.Now().Add(-PricingMaxStaleAge - time.Hour)}
	manager.catalog = old
	const readers = 32
	var workers sync.WaitGroup
	type result struct {
		catalog *pricingCatalog
		err     error
	}
	results := make(chan result, readers)
	workers.Go(func() {
		catalog, err := manager.cachedCatalog(context.Background())
		results <- result{catalog, err}
	})
	<-started
	for range readers - 1 {
		workers.Go(func() {
			catalog, err := manager.cachedCatalog(context.Background())
			results <- result{catalog, err}
		})
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	workers.Wait()
	close(results)
	for res := range results {
		require.NoError(t, res.err)
		price, ok := res.catalog.price("com")
		require.True(t, ok)
		require.Equal(t, float64(24), price)
	}
	require.Equal(t, int32(1), calls.Load())
	require.Equal(t, float64(12), old.prices["com"])
}
