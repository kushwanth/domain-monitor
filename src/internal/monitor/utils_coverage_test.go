package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRetryHonorsDeadlineAndCancellationDuringBackoff(t *testing.T) {
	failure := errors.New("temporary")
	deadlineCtx, cancelDeadline := context.WithTimeout(context.Background(), time.Second)
	defer cancelDeadline()
	value, err := retryWithBackoff(deadlineCtx, "deadline", 2*time.Second, func(int) (string, bool, time.Duration, error) {
		return "last evidence", true, 0, failure
	})
	require.Equal(t, "last evidence", value)
	require.ErrorIs(t, err, failure)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		_, err := retryWithBackoff(ctx, "cancel", 100*time.Millisecond, func(int) (string, bool, time.Duration, error) {
			close(first)
			return "", true, 0, failure
		})
		finished <- err
	}()
	<-first
	cancel()
	require.ErrorIs(t, <-finished, context.Canceled)
}

func TestHTTPHelpersHandleNilAndPartialTransportFailure(t *testing.T) {
	require.Zero(t, responseRetryAfter(nil, time.Now()))
	request, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	response, err := doHTTPRequest(nil, request)
	require.Nil(t, response)
	require.ErrorIs(t, err, ErrHTTPClientNil)

	transportErr := errors.New("connection reset")
	response, err = doHTTPWithRetry(context.Background(), "partial", &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		return &http.Response{Body: io.NopCloser(strings.NewReader("partial"))}, transportErr
	}}, RetryHTTPStatusOnly, func() (*http.Request, error) { return request, nil })
	require.Nil(t, response)
	require.ErrorIs(t, err, transportErr)
	DrainAndClose(io.NopCloser(strings.NewReader("content")), 0)
}

func TestConsoleHandlerCarriesInheritedAttributes(t *testing.T) {
	var output strings.Builder
	handler := NewConsoleHandler(&output).WithAttrs([]slog.Attr{slog.String("scope", "domain")})
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "message", 0)
	require.NoError(t, handler.Handle(context.Background(), record))
	require.Contains(t, output.String(), "scope")
}

func TestDisabledLogLevelSkipsHandler(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)
	var output strings.Builder
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelError})))
	logWithLevel(context.Background(), slog.LevelInfo, "suppressed")
	require.Empty(t, output.String())
}
