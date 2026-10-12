package monitor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindingsDeduplicateMatchingCodeAndTarget(t *testing.T) {
	condition := StateCondition{Code: CodeDNSMismatch, Target: "example.com"}
	findings := findingsFromConditions(StatusFailed, condition, condition)
	require.Len(t, findings, 1)
	require.Equal(t, FindingError, findings[0].Severity)
}

func TestUninitializedStateAndInvalidPriorityAreSafe(t *testing.T) {
	require.Empty(t, AlertPriority(255).String())
	app := &AppState{}
	_, published := app.PublishedJSON()
	require.False(t, published)
	require.Equal(t, AppConfig{}, (*AppState)(nil).configuration())
	app.SafeDispatch("warning", "warning", PriorityWarning, "", "example.com", "Example")
}

func TestDNSResultIgnoresIncompleteResults(t *testing.T) {
	state := &CheckState{DNS: make(map[string]DNSState)}
	state.storeDNSResultValue(DNSResult{Name: "example", State: DNSState{Status: StatusUnknown}})
	state.storeDNSResultValue(DNSResult{Name: "", State: DNSState{Status: StatusOK}})
	require.Empty(t, state.DNS)
	state.storeDNSResultValue(DNSResult{Name: "example", State: DNSState{Status: StatusOK}})
	require.Len(t, state.DNS, 1)
}
