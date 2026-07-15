package relay

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testRelayPayload = `{"relays":[{"url":"relay://1.2.3.4:22067/?id=6QYDUTE-SGDWWKG-2C3EKQ6-UWUNFET-DZKCTNO-OCSEYZQ-PTY6FE7-IK5ROQX"}]}`

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func discoveryTestClient(rt roundTripperFunc) *http.Client {
	return &http.Client{Transport: rt}
}

func TestDiscoverFromURLsFallsBackToMirror(t *testing.T) {
	t.Parallel()

	primaryURL := "https://primary.example/endpoint/full"
	mirrorURL := "https://mirror.example/endpoint/full"

	client := discoveryTestClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case primaryURL:
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Body:       io.NopCloser(strings.NewReader("upstream failed")),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		case mirrorURL:
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(testRelayPayload)),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		default:
			return nil, errors.New("unexpected URL")
		}
	})

	relays, err := discoverFromURLs(context.Background(), client, []string{primaryURL, mirrorURL})
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

	primaryURL := "https://primary.example/endpoint/full"
	mirrorURL := "https://mirror.example/endpoint/full"

	client := discoveryTestClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case primaryURL:
			<-r.Context().Done()
			return nil, r.Context().Err()
		case mirrorURL:
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(testRelayPayload)),
				Header:     make(http.Header),
				Request:    r,
			}, nil
		default:
			return nil, errors.New("unexpected URL")
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	relays, err := discoverFromURLs(ctx, client, []string{primaryURL, mirrorURL})
	if err != nil {
		t.Fatalf("discoverFromURLs returned error under tight deadline: %v", err)
	}

	if len(relays) != 1 {
		t.Fatalf("expected 1 relay, got %d", len(relays))
	}
}

func TestDiscoverFromURLsWithTLSFallbackRetriesWithoutCA(t *testing.T) {
	t.Parallel()

	const endpoint = "https://primary.example/endpoint/full"

	client := discoveryTestClient(func(r *http.Request) (*http.Response, error) {
		return nil, x509.UnknownAuthorityError{}
	})
	insecureClient := discoveryTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(testRelayPayload)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})

	relays, err := discoverFromURLsWithTLSFallback(
		context.Background(),
		client,
		insecureClient,
		[]string{endpoint},
	)
	if err != nil {
		t.Fatalf("discoverFromURLsWithTLSFallback returned error: %v", err)
	}

	if len(relays) != 1 {
		t.Fatalf("expected 1 relay, got %d", len(relays))
	}
}

func TestDiscoverWithStrategiesUsesFallbackStrategy(t *testing.T) {
	t.Parallel()

	const endpoint = "https://primary.example/endpoint/full"

	relays, err := discoverWithStrategies(context.Background(), []discoveryStrategy{
		{
			name:   "broken resolver",
			client: discoveryTestClient(func(r *http.Request) (*http.Response, error) { return nil, errors.New("dial failed") }),
		},
		{
			name: "working resolver",
			client: discoveryTestClient(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(testRelayPayload)),
					Header:     make(http.Header),
					Request:    r,
				}, nil
			}),
		},
	}, []string{endpoint})
	if err != nil {
		t.Fatalf("discoverWithStrategies returned error: %v", err)
	}

	if len(relays) != 1 {
		t.Fatalf("expected 1 relay, got %d", len(relays))
	}
}

func TestDiscoverWithStrategiesReturnsJoinedError(t *testing.T) {
	t.Parallel()

	const endpoint = "https://primary.example/endpoint/full"

	_, err := discoverWithStrategies(context.Background(), []discoveryStrategy{
		{
			name:   "resolver one",
			client: discoveryTestClient(func(r *http.Request) (*http.Response, error) { return nil, errors.New("first failure") }),
		},
		{
			name:   "resolver two",
			client: discoveryTestClient(func(r *http.Request) (*http.Response, error) { return nil, errors.New("second failure") }),
		},
	}, []string{endpoint})
	if err == nil {
		t.Fatal("discoverWithStrategies returned nil error")
	}

	if !strings.Contains(err.Error(), "resolver one") {
		t.Fatalf("expected joined error to include first strategy, got %v", err)
	}
	if !strings.Contains(err.Error(), "resolver two") {
		t.Fatalf("expected joined error to include second strategy, got %v", err)
	}
}

func TestParseURLExtractsAdvertisedRateLimits(t *testing.T) {
	t.Parallel()

	r, err := ParseURL("relay://1.2.3.4:22067/?id=6QYDUTE-SGDWWKG-2C3EKQ6-UWUNFET-DZKCTNO-OCSEYZQ-PTY6FE7-IK5ROQX&globalLimitBps=256000&sessionLimitBps=128000")
	if err != nil {
		t.Fatalf("ParseURL returned error: %v", err)
	}

	if r.GlobalLimitBps != 256000 {
		t.Fatalf("GlobalLimitBps = %d, want 256000", r.GlobalLimitBps)
	}
	if r.SessionLimitBps != 128000 {
		t.Fatalf("SessionLimitBps = %d, want 128000", r.SessionLimitBps)
	}
	if reason := r.DegradedReason(); !strings.Contains(reason, "global bandwidth cap") {
		t.Fatalf("DegradedReason() = %q, want low global cap", reason)
	}
}

func TestDecodeRelaysPreservesCapacityAndLoadStats(t *testing.T) {
	t.Parallel()

	payload := `{"relays":[{"url":"relay://129.153.96.88:8080/?globalLimitBps=256000&id=6QYDUTE-SGDWWKG-2C3EKQ6-UWUNFET-DZKCTNO-OCSEYZQ-PTY6FE7-IK5ROQX","stats":{"numActiveSessions":101,"kbps10s1m5m15m30m60m":[2050,2062,2049],"options":{"global-rate":256000,"per-session-rate":0}}}]}`

	relays, err := decodeRelays(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("decodeRelays returned error: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("len(relays) = %d, want 1", len(relays))
	}

	r := relays[0]
	if r.GlobalLimitBps != 256000 || r.LoadKbps != 2062 || r.ActiveSessions != 101 {
		t.Fatalf("unexpected relay metadata: %+v", r)
	}
}

func TestPartitionByQualityKeepsDegradedRelaysForFallback(t *testing.T) {
	t.Parallel()

	relays := []Relay{
		{Host: "healthy-uncapped"},
		{Host: "low-global", GlobalLimitBps: MinimumPreferredRelayBandwidth - 1},
		{Host: "low-session", SessionLimitBps: MinimumPreferredRelayBandwidth - 1},
		{
			Host:           "saturated",
			GlobalLimitBps: 10 * 1024 * 1024,
			LoadKbps:       10 * 1024 * 1024 * 8 / 1000,
		},
		{
			Host:           "healthy-limited",
			GlobalLimitBps: MinimumPreferredRelayBandwidth,
			LoadKbps:       100,
		},
	}

	preferred, degraded := PartitionByQuality(relays)
	if len(preferred) != 2 {
		t.Fatalf("len(preferred) = %d, want 2: %+v", len(preferred), preferred)
	}
	if preferred[0].Host != "healthy-uncapped" || preferred[1].Host != "healthy-limited" {
		t.Fatalf("unexpected preferred order: %+v", preferred)
	}
	if len(degraded) != 3 {
		t.Fatalf("len(degraded) = %d, want 3: %+v", len(degraded), degraded)
	}
	if degraded[0].Host != "low-global" || degraded[1].Host != "low-session" || degraded[2].Host != "saturated" {
		t.Fatalf("unexpected degraded order: %+v", degraded)
	}
}
