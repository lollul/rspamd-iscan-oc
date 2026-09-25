package rspamc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testClient(serverURL string, timeout time.Duration) *Client {
	return New(slog.New(slog.DiscardHandler), serverURL, "secret", timeout)
}

func TestCheckTimesOut(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)

	client := testClient(server.URL, 20*time.Millisecond)
	_, err := client.Check(context.Background(), bytes.NewBufferString("message"))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline error, got %v", err)
	}
}

func TestTransportErrorsAreReturned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client := testClient(server.URL, time.Second)
	server.Close()

	_, err := client.Check(context.Background(), bytes.NewBufferString("message"))
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestLearnAcceptsJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	client := testClient(server.URL, time.Second)
	if err := client.Ham(context.Background(), bytes.NewBufferString("message")); err != nil {
		t.Fatalf("expected learning request to succeed, got %v", err)
	}
}

func TestLearnRejectsMultipleChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMultipleChoices)
	}))
	defer server.Close()

	client := testClient(server.URL, time.Second)
	if err := client.Ham(context.Background(), bytes.NewBufferString("message")); err == nil {
		t.Fatal("expected 300 response to fail")
	}
}

func TestLearnAcceptsAlreadyLearnedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAlreadyReported)
	}))
	defer server.Close()

	client := testClient(server.URL, time.Second)
	if err := client.Spam(context.Background(), bytes.NewBufferString("message")); err != nil {
		t.Fatalf("expected already-learned response to succeed, got %v", err)
	}
}

func TestHTTPStatusErrorRetryability(t *testing.T) {
	if !(&HTTPStatusError{StatusCode: http.StatusServiceUnavailable}).Retryable() {
		t.Fatal("expected 503 to be retryable")
	}
	if (&HTTPStatusError{StatusCode: http.StatusBadRequest}).Retryable() {
		t.Fatal("expected 400 to be permanent")
	}
}

func TestCheckRejectsUnexpectedSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := testClient(server.URL, time.Second)
	if _, err := client.Check(context.Background(), bytes.NewBufferString("message")); err == nil {
		t.Fatal("expected non-200 check response to fail")
	}
}
