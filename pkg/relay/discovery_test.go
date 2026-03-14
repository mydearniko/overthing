package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testRelayPayload = `{"relays":[{"url":"relay://1.2.3.4:22067/?id=6QYDUTE-SGDWWKG-2C3EKQ6-UWUNFET-DZKCTNO-OCSEYZQ-PTY6FE7-IK5ROQX"}]}`

func TestDiscoverFromURLsFallsBackToMirror(t *testing.T) {
	t.Parallel()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream failed", http.StatusBadGateway)
	}))
	defer primary.Close()

	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testRelayPayload))
	}))
	defer mirror.Close()

	relays, err := discoverFromURLs(context.Background(), &http.Client{}, []string{primary.URL, mirror.URL})
	if err != nil {
		t.Fatalf("discoverFromURLs returned error: %v", err)
	}

	if len(relays) != 1 {
		t.Fatalf("expected 1 relay, got %d", len(relays))
	}

	if relays[0].Host != "1.2.3.4" || relays[0].Port != "22067" {
		t.Fatalf("unexpected relay parsed: %+v", relays[0])
	}
}

func TestDiscoverFromURLsKeepsTimeForFallback(t *testing.T) {
	t.Parallel()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer primary.Close()

	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testRelayPayload))
	}))
	defer mirror.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	relays, err := discoverFromURLs(ctx, &http.Client{}, []string{primary.URL, mirror.URL})
	if err != nil {
		t.Fatalf("discoverFromURLs returned error under tight deadline: %v", err)
	}

	if len(relays) != 1 {
		t.Fatalf("expected 1 relay, got %d", len(relays))
	}
}

func TestDiscoverFromURLsWithTLSFallbackRetriesWithoutCA(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testRelayPayload))
	}))
	defer server.Close()

	relays, err := discoverFromURLsWithTLSFallback(
		context.Background(),
		&http.Client{},
		server.Client(),
		[]string{server.URL},
	)
	if err != nil {
		t.Fatalf("discoverFromURLsWithTLSFallback returned error: %v", err)
	}

	if len(relays) != 1 {
		t.Fatalf("expected 1 relay, got %d", len(relays))
	}
}
