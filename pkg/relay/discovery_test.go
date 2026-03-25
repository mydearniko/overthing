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
