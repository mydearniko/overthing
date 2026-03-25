package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mydearniko/overthing/pkg/network"
	"github.com/mydearniko/overthing/pkg/security"
)

const (
	// DiscoveryURL is the Syncthing relay discovery endpoint
	DiscoveryURL = "https://relays.syncthing.net/endpoint/full"

	// DiscoveryMirrorURL mirrors DiscoveryURL via this repository's mirror branch.
	DiscoveryMirrorURL = "https://raw.githubusercontent.com/mydearniko/overthing/mirror/endpoint/full.json"

	// DefaultDiscoveryRequestTimeout bounds a single discovery endpoint request.
	DefaultDiscoveryRequestTimeout = 10 * time.Second

	// DefaultMaxConcurrent is the default number of concurrent latency tests
	DefaultMaxConcurrent = 200

	// DefaultTestTimeout is the default timeout for each relay test
	DefaultTestTimeout = 1200 * time.Millisecond

	// DefaultProbesPerRelay is the number of probes for precise latency measurement
	DefaultProbesPerRelay = 3

	// FastMaxConcurrent allows more parallelism for quick discovery
	FastMaxConcurrent = 300

	// FastTestTimeout is the timeout for quick discovery
	FastTestTimeout = 1000 * time.Millisecond

	// FastProbesPerRelay is the number of probes for quick discovery
	FastProbesPerRelay = 1

	// FastEarlyTerminateLatency stops testing when finding a relay this fast
	// Only triggers after MinTestedBeforeEarlyStop relays AND MinTestDuration
	FastEarlyTerminateLatency = 25 * time.Millisecond

	// FastMinTestedBeforeEarlyStop ensures we test enough relays before early termination
	FastMinTestedBeforeEarlyStop = 250

	// FastMinTestDuration ensures we test for at least this long before early termination
	FastMinTestDuration = 2 * time.Second

	// TCP pre-filter constants
	DefaultTCPPreFilterTimeout     = 500 * time.Millisecond
	DefaultTCPPreFilterConcurrency = 500
	DefaultTCPPreFilterTopN        = 80
	FastTCPPreFilterTopN           = 30

	// Adaptive retry constants
	AdaptiveMinRelays         = 10
	AdaptiveMaxRetries        = 3
	AdaptiveTimeoutMultiplier = 2
)

// Dialer is a function that matches net.Dialer.DialContext
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Relay represents a Syncthing relay server
type Relay struct {
	URL      string        `json:"url"`
	ID       string        `json:"id"`
	Host     string        `json:"host"`
	Port     string        `json:"port"`
	Latency  time.Duration `json:"latency_ns"`
	Jitter   time.Duration `json:"jitter_ns,omitempty"`
	Provider string        `json:"provider,omitempty"`
}

// LatencyMS returns latency in milliseconds
func (r *Relay) LatencyMS() float64 {
	return float64(r.Latency) / float64(time.Millisecond)
}

// Score returns a composite quality score (lower is better).
// Combines latency with jitter penalty to prefer stable relays.
// With a single probe (Jitter=0), Score equals Latency.
func (r *Relay) Score() time.Duration {
	return r.Latency + r.Jitter*2
}

// Options configures the relay discovery process
type Options struct {
	// Dialer is an optional custom dialer for network connections.
	// Used for both discovery (HTTP) and latency testing.
	Dialer Dialer

	// MaxConcurrent is the maximum number of concurrent latency tests
	MaxConcurrent int

	// TestTimeout is the timeout for each individual relay test
	TestTimeout time.Duration

	// ProbesPerRelay is the number of connection probes per relay
	// The minimum latency across all probes is used (reduces jitter noise)
	ProbesPerRelay int

	// TLSCert is an optional TLS certificate to use for testing
	TLSCert *tls.Certificate

	// EarlyTerminateLatency stops testing when a relay below this latency is found
	// AND MinTestedBeforeEarlyStop relays have been tested
	// AND MinTestDuration has elapsed.
	// Set to 0 to disable early termination.
	EarlyTerminateLatency time.Duration

	// MinTestedBeforeEarlyStop is the minimum number of relays that must complete
	// testing before early termination can trigger.
	MinTestedBeforeEarlyStop int

	// MinTestDuration is the minimum time that must elapse before early termination
	// can trigger. This ensures geographically distant relays have time to respond.
	MinTestDuration time.Duration

	// TCPPreFilterTimeout enables two-phase testing. If > 0, a quick TCP
	// reachability scan runs before TLS verification.
	TCPPreFilterTimeout time.Duration

	// TCPPreFilterConcurrency controls parallelism for the TCP scan phase.
	TCPPreFilterConcurrency int

	// TCPPreFilterTopN limits how many TCP-reachable relays proceed to TLS testing.
	TCPPreFilterTopN int

	// OnTCPPreFilter is called after TCP pre-filter completes.
	OnTCPPreFilter func(total, reachable int)

	// OnFetchStart is called when relay list fetch begins
	OnFetchStart func()

	// OnFetchComplete is called when relay list is fetched with the count
	OnFetchComplete func(count int)

	// OnTestStart is called when testing begins with total relay count
	OnTestStart func(total int)

	// OnProgress is called after each relay is tested
	OnProgress func(tested, total int)

	// OnResult is called when a relay test completes (success or failure)
	OnResult func(relay Relay, err error)

	// OnBestSoFar is called when a new best (lowest latency) relay is found
	OnBestSoFar func(relay Relay, tested int)

	// OnEarlyStop is called when early termination triggers
	// Includes the tested count at the time of termination
	OnEarlyStop func(relay Relay, testedCount int)
}

// DefaultOptions returns options for thorough relay discovery.
func DefaultOptions() Options {
	return Options{
		MaxConcurrent:            DefaultMaxConcurrent,
		TestTimeout:              DefaultTestTimeout,
		ProbesPerRelay:           DefaultProbesPerRelay,
		EarlyTerminateLatency:    0,
		MinTestedBeforeEarlyStop: 0,
		MinTestDuration:          0,
		TCPPreFilterTimeout:      DefaultTCPPreFilterTimeout,
		TCPPreFilterConcurrency:  DefaultTCPPreFilterConcurrency,
		TCPPreFilterTopN:         DefaultTCPPreFilterTopN,
	}
}

// FastOptions returns options for quick relay discovery.
func FastOptions() Options {
	return Options{
		MaxConcurrent:            FastMaxConcurrent,
		TestTimeout:              FastTestTimeout,
		ProbesPerRelay:           FastProbesPerRelay,
		EarlyTerminateLatency:    FastEarlyTerminateLatency,
		MinTestedBeforeEarlyStop: FastMinTestedBeforeEarlyStop,
		MinTestDuration:          FastMinTestDuration,
		TCPPreFilterTimeout:      DefaultTCPPreFilterTimeout,
		TCPPreFilterConcurrency:  DefaultTCPPreFilterConcurrency,
		TCPPreFilterTopN:         FastTCPPreFilterTopN,
	}
}

// Global cache for relay discovery results
var (
	cachedRelay     *Relay
	cachedRelayTime time.Time
	cachedRelayMu   sync.RWMutex
	cacheValidFor   = 5 * time.Minute
)

type discoveryStrategy struct {
	name           string
	client         *http.Client
	insecureClient *http.Client
}

// Discover fetches the list of available relays from the Syncthing endpoint,
// falling back to this repository's mirror if the primary endpoint fails.
// When no custom dialer is provided it races multiple resolver strategies:
// the normal platform resolver, the bootstrap DNS pool, and each bootstrap DNS
// server individually. If all network-based discovery fails, it returns an error.
func Discover(ctx context.Context, dialer Dialer) ([]Relay, error) {
	endpoints := []string{DiscoveryURL, DiscoveryMirrorURL}
	return discoverWithStrategies(ctx, discoveryStrategies(dialer), endpoints)
}

func discoveryStrategies(dialer Dialer) []discoveryStrategy {
	if dialer != nil {
		return []discoveryStrategy{newDiscoveryStrategy("custom dialer", dialer)}
	}

	strategies := []discoveryStrategy{
		newDiscoveryStrategy("system resolver", network.NewDialer(DefaultDiscoveryRequestTimeout).DialContext),
	}

	bootstrapServers := network.BootstrapDNSServers()
	if len(bootstrapServers) == 0 {
		return strategies
	}

	strategies = append(strategies, newDiscoveryStrategy("bootstrap DNS pool", network.NewBootstrapDialer(DefaultDiscoveryRequestTimeout).DialContext))

	for _, server := range bootstrapServers {
		strategies = append(strategies, newDiscoveryStrategy(
			fmt.Sprintf("bootstrap DNS %s", server),
			network.NewDNSDialer(DefaultDiscoveryRequestTimeout, []string{server}).DialContext,
		))
	}

	return strategies
}

func newDiscoveryStrategy(name string, dialer Dialer) discoveryStrategy {
	return discoveryStrategy{
		name:           name,
		client:         newDiscoveryHTTPClient(dialer, false),
		insecureClient: newDiscoveryHTTPClient(dialer, true),
	}
}

func discoverWithStrategies(ctx context.Context, strategies []discoveryStrategy, endpoints []string) ([]Relay, error) {
	if len(strategies) == 0 {
		return nil, fmt.Errorf("no discovery strategies configured")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		relays []Relay
		err    error
	}

	results := make(chan result, len(strategies))

	for _, strategy := range strategies {
		strategy := strategy
		go func() {
			relays, err := discoverFromURLsWithTLSFallback(ctx, strategy.client, strategy.insecureClient, endpoints)
			if err != nil {
				err = fmt.Errorf("%s: %w", strategy.name, err)
			}
			results <- result{relays: relays, err: err}
		}()
	}

	var errs []error

	for range strategies {
		result := <-results
		if result.err == nil {
			cancel()
			return result.relays, nil
		}
		errs = append(errs, result.err)
	}

	return nil, fmt.Errorf("fetch relays from discovery endpoints: %w", errors.Join(errs...))
}

func discoverFromURLs(ctx context.Context, client *http.Client, endpoints []string) ([]Relay, error) {
	if client == nil {
		client = &http.Client{}
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no discovery endpoints configured")
	}

	var errs []error

	for i, endpoint := range endpoints {
		relays, err := discoverFromURL(ctx, client, endpoint, len(endpoints)-i)
		if err == nil {
			return relays, nil
		}

		errs = append(errs, err)

		if ctx.Err() != nil {
			break
		}
	}

	return nil, fmt.Errorf("fetch relays from discovery endpoints: %w", errors.Join(errs...))
}

func discoverFromURLsWithTLSFallback(ctx context.Context, client *http.Client, insecureClient *http.Client, endpoints []string) ([]Relay, error) {
	relays, err := discoverFromURLs(ctx, client, endpoints)
	if err == nil || insecureClient == nil || !shouldRetryDiscoveryWithoutCA(err) {
		return relays, err
	}

	// Discovery bootstrap is public metadata, and overthing still verifies
	// relay IDs and the peer device ID after the relay is selected.
	return discoverFromURLs(ctx, insecureClient, endpoints)
}

func discoverFromURL(ctx context.Context, client *http.Client, endpoint string, remainingEndpoints int) ([]Relay, error) {
	attemptCtx := ctx
	cancel := func() {}

	if timeout := discoveryAttemptTimeout(ctx, remainingEndpoints); timeout > 0 {
		attemptCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	req, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: create request: %w", endpoint, err)
	}
	req.Header.Set("User-Agent", "github.com/mydearniko/overthing/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: request failed: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected status: %d", endpoint, resp.StatusCode)
	}

	relays, err := decodeRelays(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: decode response: %w", endpoint, err)
	}
	if len(relays) == 0 {
		return nil, fmt.Errorf("%s: no relays in response", endpoint)
	}

	return relays, nil
}

func newDiscoveryHTTPClient(dialer Dialer, insecureTLS bool) *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	return &http.Client{Transport: transport}
}

func shouldRetryDiscoveryWithoutCA(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}

	var systemRootsErr x509.SystemRootsError
	return errors.As(err, &systemRootsErr)
}

func discoveryAttemptTimeout(ctx context.Context, remainingEndpoints int) time.Duration {
	if remainingEndpoints < 1 {
		remainingEndpoints = 1
	}

	timeout := DefaultDiscoveryRequestTimeout

	deadline, ok := ctx.Deadline()
	if !ok {
		return timeout
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}

	split := remaining / time.Duration(remainingEndpoints)
	if split <= 0 {
		split = remaining
	}
	if split < timeout {
		timeout = split
	}

	return timeout
}

func decodeRelays(r io.Reader) ([]Relay, error) {
	// The endpoint returns: { "key": [ {url: "..."}, ... ], ... }
	var data map[string][]struct {
		URL string `json:"url"`
	}

	if err := json.NewDecoder(r).Decode(&data); err != nil {
		return nil, err
	}

	var relays []Relay
	seen := make(map[string]bool)

	for _, entries := range data {
		for _, entry := range entries {
			if entry.URL == "" || seen[entry.URL] {
				continue
			}
			seen[entry.URL] = true

			relay, err := ParseURL(entry.URL)
			if err != nil {
				continue
			}
			relays = append(relays, *relay)
		}
	}

	return relays, nil
}

// ParseURL parses a relay URL and extracts its components
func ParseURL(rawURL string) (*Relay, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "relay" {
		return nil, fmt.Errorf("invalid scheme: %s", u.Scheme)
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, err
	}

	id := u.Query().Get("id")
	if id == "" {
		return nil, fmt.Errorf("missing relay ID")
	}

	provider := u.Query().Get("providedBy")

	return &Relay{
		URL:      rawURL,
		ID:       security.NormalizeID(id),
		Host:     host,
		Port:     port,
		Provider: provider,
	}, nil
}

// tcpProbe performs a quick TCP connect to measure reachability and RTT.
// This is much cheaper than a full TLS handshake.
func tcpProbe(ctx context.Context, addr string, dialer Dialer) (time.Duration, error) {
	start := time.Now()
	var conn net.Conn
	var err error
	if dialer != nil {
		conn, err = dialer(ctx, "tcp", addr)
	} else {
		d := &net.Dialer{}
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

type tcpResult struct {
	index int
	rtt   time.Duration
}

// tcpPreFilter probes all relays with a quick TCP connect and returns
// the fastest reachable relays sorted by TCP RTT, up to topN.
// It uses adaptive retry: if too few relays respond within the timeout,
// it retries failed relays with a longer timeout.
func tcpPreFilter(ctx context.Context, relays []Relay, timeout time.Duration, maxConcurrent int, topN int, dialer Dialer) []Relay {
	if len(relays) == 0 {
		return nil
	}
	if topN <= 0 || topN > len(relays) {
		topN = len(relays)
	}
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultTCPPreFilterConcurrency
	}

	// Track which relays have been successfully probed
	type indexedResult struct {
		relay Relay
		rtt   time.Duration
	}

	var successful []indexedResult
	pending := make([]int, len(relays))
	for i := range pending {
		pending[i] = i
	}

	currentTimeout := timeout

	for attempt := 0; attempt <= AdaptiveMaxRetries; attempt++ {
		if ctx.Err() != nil {
			break
		}
		if attempt > 0 && (len(successful) >= AdaptiveMinRelays || len(successful) >= topN) {
			break // enough relays found
		}
		if attempt > 0 {
			currentTimeout *= time.Duration(AdaptiveTimeoutMultiplier)
		}

		var mu sync.Mutex
		var newSuccessful []indexedResult
		var stillPending []int
		var wg sync.WaitGroup
		sem := make(chan struct{}, maxConcurrent)

		for _, idx := range pending {
			idx := idx
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}

				probeCtx, cancel := context.WithTimeout(ctx, currentTimeout)
				defer cancel()

				addr := net.JoinHostPort(relays[idx].Host, relays[idx].Port)
				rtt, err := tcpProbe(probeCtx, addr, dialer)

				mu.Lock()
				if err == nil {
					r := relays[idx]
					newSuccessful = append(newSuccessful, indexedResult{relay: r, rtt: rtt})
				} else {
					stillPending = append(stillPending, idx)
				}
				mu.Unlock()
			}()
		}
		wg.Wait()

		successful = append(successful, newSuccessful...)
		pending = stillPending

		if len(pending) == 0 {
			break
		}
	}

	// Sort by TCP RTT
	sort.Slice(successful, func(i, j int) bool {
		return successful[i].rtt < successful[j].rtt
	})

	if len(successful) > topN {
		successful = successful[:topN]
	}

	filtered := make([]Relay, len(successful))
	for i, r := range successful {
		filtered[i] = r.relay
	}
	return filtered
}

// probeLatency does a single TCP+TLS probe and returns the latency
func probeLatency(ctx context.Context, addr string, relayID string, tlsCert *tls.Certificate, dialer Dialer) (time.Duration, error) {
	start := time.Now()

	var conn net.Conn
	var err error

	if dialer != nil {
		conn, err = dialer(ctx, "tcp", addr)
	} else {
		d := network.NewDialer(0)
		conn, err = d.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return 0, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"bep-relay"},
		MinVersion:         tls.VersionTLS13,
	}
	if tlsCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*tlsCert}
	}

	tlsConn := tls.Client(conn, tlsConfig)

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	tlsConn.SetDeadline(deadline)

	if err := tlsConn.Handshake(); err != nil {
		return 0, fmt.Errorf("tls: %w", err)
	}

	// Verify relay ID
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return 0, fmt.Errorf("no peer certificates")
	}

	remoteID := security.NormalizeID(security.GetDeviceID(peerCerts[0].Raw))
	if remoteID != relayID {
		return 0, fmt.Errorf("ID mismatch")
	}

	return time.Since(start), nil
}

// TestLatency tests the connection latency to a relay with multiple probes.
func TestLatency(ctx context.Context, r *Relay, opts *Options) error {
	if opts == nil {
		defaultOpts := DefaultOptions()
		opts = &defaultOpts
	}

	probes := opts.ProbesPerRelay
	if probes < 1 {
		probes = 1
	}

	addr := net.JoinHostPort(r.Host, r.Port)

	// Optimization: Pre-resolve IP if NO custom dialer is present.
	// If a custom dialer is present, we cannot assume the default resolver
	// routes correctly, or the dialer might be a proxy requiring hostnames.
	if opts.Dialer == nil {
		ips, err := network.LookupIP(ctx, r.Host)
		if err == nil {
			var targetIP string
			for _, ip := range ips {
				if ip.To4() != nil {
					targetIP = ip.String()
					break
				}
			}
			if targetIP == "" && len(ips) > 0 {
				targetIP = ips[0].String()
			}
			if targetIP != "" {
				addr = net.JoinHostPort(targetIP, r.Port)
			}
		}
	}

	var minLatency time.Duration
	var maxLatency time.Duration
	var successCount int

	for i := 0; i < probes; i++ {
		if ctx.Err() != nil {
			if minLatency > 0 {
				break
			}
			return ctx.Err()
		}

		probeCtx, cancel := context.WithTimeout(ctx, opts.TestTimeout)
		latency, err := probeLatency(probeCtx, addr, r.ID, opts.TLSCert, opts.Dialer)
		cancel()

		if err != nil {
			if i == 0 {
				return err
			}
			continue
		}

		successCount++
		if minLatency == 0 || latency < minLatency {
			minLatency = latency
		}
		if latency > maxLatency {
			maxLatency = latency
		}
	}

	if minLatency == 0 {
		return fmt.Errorf("all probes failed")
	}

	r.Latency = minLatency
	if successCount > 1 {
		r.Jitter = maxLatency - minLatency
	}

	return nil
}

// FindFastest discovers relays and returns the one with lowest latency.
func FindFastest(ctx context.Context, opts *Options) (*Relay, error) {
	// Check cache first (only if no custom dialer, as dialers might change context)
	if opts == nil || opts.Dialer == nil {
		cachedRelayMu.RLock()
		if cachedRelay != nil && time.Since(cachedRelayTime) < cacheValidFor {
			r := *cachedRelay
			cachedRelayMu.RUnlock()
			return &r, nil
		}
		cachedRelayMu.RUnlock()
	}

	results, err := FindFastestN(ctx, 1, opts)
	if err != nil {
		return nil, err
	}

	// Update cache (only if default dialer)
	if opts == nil || opts.Dialer == nil {
		cachedRelayMu.Lock()
		cachedRelay = &results[0]
		cachedRelayTime = time.Now()
		cachedRelayMu.Unlock()
	}

	return &results[0], nil
}

// FindFastestN discovers relays and returns the N fastest
func FindFastestN(ctx context.Context, n int, opts *Options) ([]Relay, error) {
	if opts == nil {
		defaultOpts := DefaultOptions()
		opts = &defaultOpts
	}

	if opts.OnFetchStart != nil {
		opts.OnFetchStart()
	}

	relays, err := Discover(ctx, opts.Dialer)
	if err != nil {
		return nil, err
	}

	if opts.OnFetchComplete != nil {
		opts.OnFetchComplete(len(relays))
	}

	return TestAllAndSort(ctx, relays, n, opts)
}

// TestAllAndSort tests all provided relays and returns up to n fastest ones.
// When TCPPreFilterTimeout > 0, it runs a two-phase strategy:
// Phase 1: Quick TCP reachability scan to eliminate unreachable relays.
// Phase 2: Full TLS+ID verification of the top TCP-reachable candidates.
func TestAllAndSort(ctx context.Context, relays []Relay, n int, opts *Options) ([]Relay, error) {
	if opts == nil {
		defaultOpts := DefaultOptions()
		opts = &defaultOpts
	}

	if len(relays) == 0 {
		return nil, fmt.Errorf("no relays to test")
	}

	// Phase 1: TCP pre-filter
	if opts.TCPPreFilterTimeout > 0 {
		filtered := tcpPreFilter(ctx, relays, opts.TCPPreFilterTimeout,
			opts.TCPPreFilterConcurrency, opts.TCPPreFilterTopN, opts.Dialer)
		if len(filtered) > 0 {
			if opts.OnTCPPreFilter != nil {
				opts.OnTCPPreFilter(len(relays), len(filtered))
			}
			relays = filtered
		}
		// If no relays passed TCP pre-filter, fall through to test all
	}

	maxConcurrent := opts.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrent
	}

	testCtx, cancelTest := context.WithCancel(ctx)
	defer cancelTest()

	startTime := time.Now()

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrent)

	var mu sync.Mutex
	var available []Relay
	var bestRelay *Relay
	var bestLatency time.Duration

	var tested int32
	var stopped int32

	if opts.OnTestStart != nil {
		opts.OnTestStart(len(relays))
	}

	for i := range relays {
		relay := relays[i]
		wg.Add(1)

		go func(r Relay) {
			defer wg.Done()

			if atomic.LoadInt32(&stopped) != 0 {
				return
			}

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-testCtx.Done():
				return
			}

			if atomic.LoadInt32(&stopped) != 0 {
				return
			}

			testErr := TestLatency(testCtx, &r, opts)
			testedCount := int(atomic.AddInt32(&tested, 1))

			mu.Lock()

			if testErr == nil {
				available = append(available, r)

				if bestRelay == nil || r.Latency < bestLatency {
					bestLatency = r.Latency
					rCopy := r
					bestRelay = &rCopy

					if opts.OnBestSoFar != nil {
						opts.OnBestSoFar(r, testedCount)
					}
				}
			}

			if opts.OnProgress != nil {
				opts.OnProgress(testedCount, len(relays))
			}

			if opts.OnResult != nil {
				opts.OnResult(r, testErr)
			}

			if opts.EarlyTerminateLatency > 0 &&
				testedCount >= opts.MinTestedBeforeEarlyStop &&
				time.Since(startTime) >= opts.MinTestDuration &&
				bestRelay != nil &&
				bestLatency <= opts.EarlyTerminateLatency &&
				atomic.CompareAndSwapInt32(&stopped, 0, 1) {

				if opts.OnEarlyStop != nil {
					opts.OnEarlyStop(*bestRelay, testedCount)
				}
				cancelTest()
			}

			mu.Unlock()
		}(relay)
	}

	wg.Wait()

	if ctx.Err() != nil && atomic.LoadInt32(&stopped) == 0 {
		return nil, ctx.Err()
	}

	if len(available) == 0 {
		return nil, fmt.Errorf("no available relays (tested %d)", atomic.LoadInt32(&tested))
	}

	sort.Slice(available, func(i, j int) bool {
		return available[i].Score() < available[j].Score()
	})

	if n <= 0 || n > len(available) {
		n = len(available)
	}

	return available[:n], nil
}

func ClearCache() {
	cachedRelayMu.Lock()
	cachedRelay = nil
	cachedRelayMu.Unlock()
}
