package monitor

import (
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestProductionSourceConventions(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve convention test path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
	sourceRoot := filepath.Join(repositoryRoot, "src")

	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path == filepath.Join(repositoryRoot, ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".go" && !strings.HasPrefix(path, sourceRoot+string(filepath.Separator)) {
			t.Errorf("Go source must live under src: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}

	err = filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		checkProductionFileConventions(t, sourceRoot, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk production source: %v", err)
	}
}

func TestNilAppStateAccessors(t *testing.T) {
	t.Parallel()

	var app *AppState
	body, ok := app.PublishedJSON()
	assert.Nil(t, body)
	assert.False(t, ok)
	assert.Empty(t, app.Config())
	assert.NotEmpty(t, app.Resolvers())
	assert.NotPanics(t, func() {
		app.SafeDispatch("message", "redacted", PriorityDefault, TagSkull, "example.com", "example")
	})
}

func checkProductionFileConventions(t *testing.T, sourceRoot, path string) {
	t.Helper()

	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		t.Errorf("parse %s: %v", path, err)
		return
	}
	relativePath, err := filepath.Rel(sourceRoot, path)
	if err != nil {
		t.Errorf("resolve source path %s: %v", path, err)
		return
	}

	allowedStrings := make(map[token.Pos]struct{})
	for _, spec := range file.Imports {
		allowedStrings[spec.Path.Pos()] = struct{}{}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if field, ok := node.(*ast.Field); ok && field.Tag != nil {
			allowedStrings[field.Tag.Pos()] = struct{}{}
		}
		return true
	})

	constantsFile := filepath.Base(path) == "constants.go"
	typesFile := filepath.ToSlash(relativePath) == "internal/monitor/types.go"
	ast.Inspect(file, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.GenDecl:
			if current.Tok == token.TYPE && !typesFile {
				t.Errorf("production type declarations belong in internal/monitor/types.go: %s:%d", relativePath, fileSet.Position(current.Pos()).Line)
			}
		case *ast.BasicLit:
			if current.Kind == token.STRING && !constantsFile {
				if _, allowed := allowedStrings[current.Pos()]; !allowed {
					t.Errorf("runtime string literals belong in constants.go: %s:%d", relativePath, fileSet.Position(current.Pos()).Line)
				}
			}
		case *ast.SelectorExpr:
			identifier, ok := current.X.(*ast.Ident)
			if !ok {
				break
			}
			bypassesLoggingUtility := identifier.Name == "log" ||
				(identifier.Name == "slog" && current.Sel.Name != "New" && current.Sel.Name != "NewRecord" && current.Sel.Name != "SetDefault" && current.Sel.Name != "Default") ||
				(identifier.Name == "fmt" && strings.HasPrefix(current.Sel.Name, "Print"))
			if bypassesLoggingUtility && filepath.Base(path) != "utils.go" {
				t.Errorf("production logging must use project utilities: %s:%d", relativePath, fileSet.Position(current.Pos()).Line)
			}
		}
		return true
	})
}

type dummyStringer struct{}

func (dummyStringer) String() string { return "dummy-string" }

// MockHTTPClient implements HTTPDoer for tests.
type MockHTTPClient struct {
	MockDo func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.MockDo != nil {
		return m.MockDo(req)
	}
	return nil, nil
}

// MockDNSResolver implements Resolver for tests.
type MockDNSResolver struct {
	MockExchangeContext func(ctx context.Context, message *dns.Msg, address string) (*dns.Msg, time.Duration, error)
}

func (m *MockDNSResolver) ExchangeContext(ctx context.Context, message *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
	if m.MockExchangeContext != nil {
		return m.MockExchangeContext(ctx, message, address)
	}
	return nil, 0, nil
}

// MockWHOISClient implements WHOISQuerier for tests.
type MockWHOISClient struct {
	MockQuery func(ctx context.Context, domain, server string) (string, error)
}

func (m *MockWHOISClient) Query(ctx context.Context, domain, server string) (string, error) {
	if m.MockQuery != nil {
		return m.MockQuery(ctx, domain, server)
	}
	return StrEmpty, nil
}

type recordingNotifier struct {
	*NotificationManager
	alerts []Alert
}

func newRecordingNotifier() *recordingNotifier {
	notifier := NewNotificationManager("https://ntfy.invalid/test", StrEmpty, StrEmpty, StrEmpty)
	notifier.HTTPClient = &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(StrEmpty))}, nil
	}}
	return &recordingNotifier{NotificationManager: notifier}
}

func (n *recordingNotifier) Dispatch(message, redacted string, priority AlertPriority, tag AlertTag, domain, name string) {
	n.NotificationManager.Dispatch(message, redacted, priority, tag, domain, name)
	n.captureAndFlush()
}

func (n *recordingNotifier) captureAndFlush() {
	n.alerts = append(n.alerts, n.alertBatch...)
	n.Flush()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

type mockTransport struct {
	attempts int
	mu       sync.Mutex
}

func (m *mockTransport) RoundTrip(*http.Request) (*http.Response, error) {
	m.mu.Lock()
	m.attempts++
	m.mu.Unlock()

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Header:     make(http.Header),
	}, nil
}

type failingProviderReader struct{}

func (failingProviderReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

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

func decodePublishedState(t *testing.T, body []byte) CheckState {
	t.Helper()
	var wire apiState
	if err := jsonv2.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	return wire.checkState()
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
