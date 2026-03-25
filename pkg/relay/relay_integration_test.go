package relay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- Unit tests for new functionality ----

func TestRelayScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		latency time.Duration
		jitter  time.Duration
		want    time.Duration
	}{
		{"zero jitter", 50 * time.Millisecond, 0, 50 * time.Millisecond},
		{"low jitter", 50 * time.Millisecond, 5 * time.Millisecond, 60 * time.Millisecond},
		{"high jitter", 50 * time.Millisecond, 30 * time.Millisecond, 110 * time.Millisecond},
		{"high latency low jitter", 200 * time.Millisecond, 2 * time.Millisecond, 204 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Relay{Latency: tt.latency, Jitter: tt.jitter}
			got := r.Score()
			if got != tt.want {
				t.Errorf("Score() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRelayScorePreferStable(t *testing.T) {
	t.Parallel()

	// A slightly slower but stable relay should beat an unstable one
	stable := Relay{Latency: 60 * time.Millisecond, Jitter: 0}
	unstable := Relay{Latency: 50 * time.Millisecond, Jitter: 20 * time.Millisecond}

	if stable.Score() >= unstable.Score() {
		t.Errorf("stable relay (score=%v) should beat unstable (score=%v)",
			stable.Score(), unstable.Score())
	}
}

func TestTCPPreFilterSortsAndLimits(t *testing.T) {
	t.Parallel()

	// Set up a few local TCP listeners to act as "relays"
	var listeners []net.Listener
	var relays []Relay
	for i := 0; i < 5; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		listeners = append(listeners, ln)

		_, port, _ := net.SplitHostPort(ln.Addr().String())
		relays = append(relays, Relay{
			Host: "127.0.0.1",
			Port: port,
			ID:   fmt.Sprintf("TEST-ID-%d", i),
		})
	}

	// Also add unreachable relays
	relays = append(relays, Relay{Host: "192.0.2.1", Port: "22067", ID: "UNREACHABLE-1"})
	relays = append(relays, Relay{Host: "192.0.2.2", Port: "22067", ID: "UNREACHABLE-2"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filtered := tcpPreFilter(ctx, relays, 500*time.Millisecond, 100, 3, nil)

	if len(filtered) != 3 {
		t.Fatalf("expected 3 filtered relays, got %d", len(filtered))
	}

	// All filtered relays should be the local ones (127.0.0.1)
	for _, r := range filtered {
		if r.Host != "127.0.0.1" {
			t.Errorf("unexpected relay in filtered results: %s:%s", r.Host, r.Port)
		}
	}
}

func TestTCPPreFilterAdaptiveRetry(t *testing.T) {
	t.Parallel()

	// Create one real listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Mix of reachable and unreachable
	relays := []Relay{
		{Host: "192.0.2.1", Port: "22067", ID: "UNREACHABLE-1"},
		{Host: "192.0.2.2", Port: "22067", ID: "UNREACHABLE-2"},
		{Host: "127.0.0.1", Port: port, ID: "REACHABLE-1"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// With a very short initial timeout, the unreachable ones fail fast
	// and the reachable one should be found
	filtered := tcpPreFilter(ctx, relays, 100*time.Millisecond, 100, 10, nil)

	if len(filtered) < 1 {
		t.Fatal("expected at least 1 reachable relay after adaptive retry")
	}

	if filtered[0].Host != "127.0.0.1" {
		t.Errorf("expected reachable relay first, got %s", filtered[0].Host)
	}
}

func TestTCPPreFilterEmptyInput(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	result := tcpPreFilter(ctx, nil, 100*time.Millisecond, 100, 10, nil)
	if result != nil {
		t.Errorf("expected nil for empty input, got %v", result)
	}
}

func TestTCPPreFilterContextCancel(t *testing.T) {
	t.Parallel()

	relays := []Relay{
		{Host: "192.0.2.1", Port: "22067", ID: "UNREACHABLE-1"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled

	filtered := tcpPreFilter(ctx, relays, 500*time.Millisecond, 100, 10, nil)
	// Should return quickly with 0 results
	if len(filtered) != 0 {
		t.Errorf("expected 0 relays with cancelled context, got %d", len(filtered))
	}
}

func TestDefaultOptionsIncludesTCPPreFilter(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()
	if opts.TCPPreFilterTimeout <= 0 {
		t.Error("DefaultOptions should have TCPPreFilterTimeout > 0")
	}
	if opts.TCPPreFilterConcurrency <= 0 {
		t.Error("DefaultOptions should have TCPPreFilterConcurrency > 0")
	}
	if opts.TCPPreFilterTopN <= 0 {
		t.Error("DefaultOptions should have TCPPreFilterTopN > 0")
	}
}

func TestFastOptionsIncludesTCPPreFilter(t *testing.T) {
	t.Parallel()

	opts := FastOptions()
	if opts.TCPPreFilterTimeout <= 0 {
		t.Error("FastOptions should have TCPPreFilterTimeout > 0")
	}
	if opts.TCPPreFilterTopN <= 0 {
		t.Error("FastOptions should have TCPPreFilterTopN > 0")
	}
	if opts.TCPPreFilterTopN >= DefaultTCPPreFilterTopN {
		t.Errorf("FastOptions TCPPreFilterTopN (%d) should be less than DefaultOptions (%d)",
			opts.TCPPreFilterTopN, DefaultTCPPreFilterTopN)
	}
}

// ---- Integration tests (real network) ----

func TestIntegration_LiveDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	relays, err := Discover(ctx, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	t.Logf("Discovered %d relays in %s", len(relays), elapsed)

	if len(relays) < 10 {
		t.Errorf("Expected at least 10 relays, got %d", len(relays))
	}

	// Spot check structure
	for i, r := range relays[:min(5, len(relays))] {
		if r.Host == "" || r.Port == "" || r.ID == "" {
			t.Errorf("relay[%d] missing fields: %+v", i, r)
		}
	}
}

func TestIntegration_TCPReachability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	relays, err := Discover(ctx, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	start := time.Now()
	reachable := tcpPreFilter(ctx, relays, 2*time.Second, 500, len(relays), nil)
	elapsed := time.Since(start)

	t.Logf("TCP reachable: %d/%d in %s", len(reachable), len(relays), elapsed)

	if len(reachable) < 5 {
		t.Errorf("Expected at least 5 TCP-reachable relays, got %d", len(reachable))
	}

	// Log top 10 by TCP RTT (embedded in the filter order)
	for i, r := range reachable[:min(10, len(reachable))] {
		t.Logf("  TCP #%d: %s:%s", i+1, r.Host, r.Port)
	}
}

func TestIntegration_TCPPreFilter_SpeedsUpDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	relays, err := Discover(ctx, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// Phase 1: TCP scan
	start := time.Now()
	filtered := tcpPreFilter(ctx, relays, DefaultTCPPreFilterTimeout,
		DefaultTCPPreFilterConcurrency, DefaultTCPPreFilterTopN, nil)
	tcpElapsed := time.Since(start)

	if len(filtered) == 0 {
		t.Fatal("TCP pre-filter returned 0 relays")
	}

	t.Logf("TCP pre-filter: %d/%d relays in %s", len(filtered), len(relays), tcpElapsed)

	// The TCP pre-filter should complete in a reasonable time
	if tcpElapsed > 10*time.Second {
		t.Errorf("TCP pre-filter took too long: %s", tcpElapsed)
	}
}

func TestIntegration_TLSProbe_SingleRelay(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use embedded relays for quick test
	relays := EmbeddedRelays()
	if len(relays) == 0 {
		t.Skip("no embedded relays available")
	}

	// Find first TCP-reachable relay
	reachable := tcpPreFilter(ctx, relays, 2*time.Second, 100, 5, nil)
	if len(reachable) == 0 {
		t.Skip("no TCP-reachable embedded relays")
	}

	r := reachable[0]
	opts := DefaultOptions()
	opts.ProbesPerRelay = 3
	opts.TCPPreFilterTimeout = 0 // skip TCP pre-filter in TestLatency

	start := time.Now()
	err := TestLatency(ctx, &r, &opts)
	elapsed := time.Since(start)

	if err != nil {
		t.Logf("TLS probe failed for %s:%s: %v", r.Host, r.Port, err)
		// Try next reachable relay
		if len(reachable) > 1 {
			r = reachable[1]
			err = TestLatency(ctx, &r, &opts)
			if err != nil {
				t.Skipf("TLS probe failed for multiple relays, possibly firewalled")
			}
		} else {
			t.Skip("TLS probe failed, possibly firewalled")
		}
	}

	t.Logf("TLS probe: %s:%s latency=%s jitter=%s score=%s (elapsed=%s)",
		r.Host, r.Port, r.Latency, r.Jitter, r.Score(), elapsed)

	if r.Latency <= 0 {
		t.Error("Expected positive latency")
	}
	if r.Latency > 10*time.Second {
		t.Error("Latency seems unreasonably high")
	}
}

func TestIntegration_FindFastest_Default(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ClearCache()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var tcpTotal, tcpReachable int
	var testedCount int32

	opts := DefaultOptions()
	opts.OnTCPPreFilter = func(total, reachable int) {
		tcpTotal = total
		tcpReachable = reachable
	}
	opts.OnProgress = func(tested, total int) {
		atomic.StoreInt32(&testedCount, int32(tested))
	}

	start := time.Now()
	result, err := FindFastest(ctx, &opts)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("FindFastest: %v", err)
	}

	t.Logf("FindFastest (default):")
	t.Logf("  TCP pre-filter: %d/%d reachable", tcpReachable, tcpTotal)
	t.Logf("  TLS tested: %d", atomic.LoadInt32(&testedCount))
	t.Logf("  Best relay: %s:%s", result.Host, result.Port)
	t.Logf("  Latency: %s", result.Latency)
	t.Logf("  Jitter: %s", result.Jitter)
	t.Logf("  Score: %s", result.Score())
	t.Logf("  Total elapsed: %s", elapsed)

	if result.Latency <= 0 {
		t.Error("Expected positive latency")
	}
	if result.Latency > 5*time.Second {
		t.Error("Latency seems unreasonably high (>5s)")
	}
}

func TestIntegration_FindFastest_FastMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ClearCache()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var tcpTotal, tcpReachable int
	var earlyStopped bool
	var earlyStopCount int

	opts := FastOptions()
	opts.OnTCPPreFilter = func(total, reachable int) {
		tcpTotal = total
		tcpReachable = reachable
	}
	opts.OnEarlyStop = func(r Relay, count int) {
		earlyStopped = true
		earlyStopCount = count
	}

	start := time.Now()
	result, err := FindFastest(ctx, &opts)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("FindFastest (fast): %v", err)
	}

	t.Logf("FindFastest (fast mode):")
	t.Logf("  TCP pre-filter: %d/%d reachable", tcpReachable, tcpTotal)
	t.Logf("  Best relay: %s:%s", result.Host, result.Port)
	t.Logf("  Latency: %s", result.Latency)
	t.Logf("  Score: %s", result.Score())
	t.Logf("  Early stopped: %v (at relay #%d)", earlyStopped, earlyStopCount)
	t.Logf("  Total elapsed: %s", elapsed)

	if result.Latency <= 0 {
		t.Error("Expected positive latency")
	}
}

func TestIntegration_FindFastestN_Top5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ClearCache()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	opts := DefaultOptions()

	start := time.Now()
	results, err := FindFastestN(ctx, 5, &opts)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("FindFastestN: %v", err)
	}

	t.Logf("Top 5 relays (elapsed=%s):", elapsed)
	for i, r := range results {
		t.Logf("  #%d: %s:%s latency=%s jitter=%s score=%s",
			i+1, r.Host, r.Port, r.Latency, r.Jitter, r.Score())
	}

	if len(results) < 1 {
		t.Fatal("Expected at least 1 relay")
	}

	// Results should be sorted by score
	for i := 1; i < len(results); i++ {
		if results[i].Score() < results[i-1].Score() {
			t.Errorf("results not sorted by score: [%d]=%s > [%d]=%s",
				i-1, results[i-1].Score(), i, results[i].Score())
		}
	}
}

func TestIntegration_CompareDefaultVsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ClearCache()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	// Run fast mode
	fastOpts := FastOptions()
	fastStart := time.Now()
	fastResult, err := FindFastest(ctx, &fastOpts)
	fastElapsed := time.Since(fastStart)
	if err != nil {
		t.Fatalf("FindFastest (fast): %v", err)
	}

	ClearCache()

	// Run default mode
	defaultOpts := DefaultOptions()
	defaultStart := time.Now()
	defaultResult, err := FindFastest(ctx, &defaultOpts)
	defaultElapsed := time.Since(defaultStart)
	if err != nil {
		t.Fatalf("FindFastest (default): %v", err)
	}

	t.Logf("Comparison:")
	t.Logf("  Fast mode:    %s:%s latency=%s score=%s elapsed=%s",
		fastResult.Host, fastResult.Port, fastResult.Latency, fastResult.Score(), fastElapsed)
	t.Logf("  Default mode: %s:%s latency=%s score=%s elapsed=%s",
		defaultResult.Host, defaultResult.Port, defaultResult.Latency, defaultResult.Score(), defaultElapsed)
	t.Logf("  Speed ratio: fast is %.1fx faster", float64(defaultElapsed)/float64(fastElapsed))
}

func TestIntegration_EmbeddedRelays_Reachability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	relays := EmbeddedRelays()
	if len(relays) == 0 {
		t.Skip("no embedded relays")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	reachable := tcpPreFilter(ctx, relays, 3*time.Second, 200, len(relays), nil)
	pct := float64(len(reachable)) / float64(len(relays)) * 100

	t.Logf("Embedded relay reachability: %d/%d (%.0f%%)", len(reachable), len(relays), pct)

	if pct < 10 {
		t.Logf("WARNING: Less than 10%% of embedded relays are reachable. List may be stale.")
	}
}

func TestIntegration_CacheWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ClearCache()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	opts := FastOptions()

	// First call: cold cache
	start := time.Now()
	result1, err := FindFastest(ctx, &opts)
	coldElapsed := time.Since(start)
	if err != nil {
		t.Fatalf("FindFastest (cold): %v", err)
	}

	// Second call: warm cache
	start = time.Now()
	result2, err := FindFastest(ctx, &opts)
	warmElapsed := time.Since(start)
	if err != nil {
		t.Fatalf("FindFastest (warm): %v", err)
	}

	t.Logf("Cache test:")
	t.Logf("  Cold: %s (relay=%s:%s)", coldElapsed, result1.Host, result1.Port)
	t.Logf("  Warm: %s (relay=%s:%s)", warmElapsed, result2.Host, result2.Port)

	// Warm cache should be nearly instant
	if warmElapsed > 10*time.Millisecond {
		t.Errorf("Warm cache took %s, expected <10ms", warmElapsed)
	}

	// Should return the same relay
	if result1.Host != result2.Host || result1.Port != result2.Port {
		t.Errorf("Cache returned different relay: %s:%s vs %s:%s",
			result1.Host, result1.Port, result2.Host, result2.Port)
	}
}

func TestIntegration_TestAllAndSort_WithPreFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	relays, err := Discover(ctx, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// Test with TCP pre-filter enabled
	optsWithFilter := DefaultOptions()
	start := time.Now()
	withFilter, err := TestAllAndSort(ctx, relays, 3, &optsWithFilter)
	withFilterElapsed := time.Since(start)
	if err != nil {
		t.Fatalf("TestAllAndSort (with filter): %v", err)
	}

	// Test without TCP pre-filter
	optsNoFilter := DefaultOptions()
	optsNoFilter.TCPPreFilterTimeout = 0
	start = time.Now()
	noFilter, err := TestAllAndSort(ctx, relays, 3, &optsNoFilter)
	noFilterElapsed := time.Since(start)
	if err != nil {
		t.Fatalf("TestAllAndSort (no filter): %v", err)
	}

	t.Logf("TestAllAndSort comparison:")
	t.Logf("  With TCP pre-filter: %d results in %s", len(withFilter), withFilterElapsed)
	if len(withFilter) > 0 {
		t.Logf("    Best: %s:%s latency=%s", withFilter[0].Host, withFilter[0].Port, withFilter[0].Latency)
	}
	t.Logf("  Without TCP pre-filter: %d results in %s", len(noFilter), noFilterElapsed)
	if len(noFilter) > 0 {
		t.Logf("    Best: %s:%s latency=%s", noFilter[0].Host, noFilter[0].Port, noFilter[0].Latency)
	}
}

func TestIntegration_StressHighConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create many local listeners to simulate high relay count
	var listeners []net.Listener
	var relays []Relay
	for i := 0; i < 200; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		listeners = append(listeners, ln)

		_, port, _ := net.SplitHostPort(ln.Addr().String())
		relays = append(relays, Relay{
			Host: "127.0.0.1",
			Port: port,
			ID:   fmt.Sprintf("STRESS-%d", i),
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	filtered := tcpPreFilter(ctx, relays, 500*time.Millisecond, 500, 50, nil)
	elapsed := time.Since(start)

	t.Logf("High concurrency TCP scan: %d/%d in %s", len(filtered), len(relays), elapsed)

	if len(filtered) != 50 {
		t.Errorf("expected 50 filtered relays, got %d", len(filtered))
	}
	if elapsed > 3*time.Second {
		t.Errorf("TCP scan too slow: %s", elapsed)
	}
}

func TestIntegration_CustomDialer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ClearCache()

	var dialCount int32
	customDialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		atomic.AddInt32(&dialCount, 1)
		d := &net.Dialer{}
		return d.DialContext(ctx, network, address)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	opts := FastOptions()
	opts.Dialer = customDialer

	result, err := FindFastest(ctx, &opts)
	if err != nil {
		t.Fatalf("FindFastest with custom dialer: %v", err)
	}

	count := atomic.LoadInt32(&dialCount)
	t.Logf("Custom dialer: %d dial calls, best=%s:%s latency=%s",
		count, result.Host, result.Port, result.Latency)

	if count == 0 {
		t.Error("Custom dialer was never called")
	}
}

func TestIntegration_ParallelFindFastest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ClearCache()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// First, warm the cache
	opts := FastOptions()
	_, err := FindFastest(ctx, &opts)
	if err != nil {
		t.Fatalf("Initial FindFastest: %v", err)
	}

	// Now run 10 concurrent FindFastest calls (should all hit cache)
	var wg sync.WaitGroup
	results := make([]*Relay, 10)
	errs := make([]error, 10)

	start := time.Now()
	for i := 0; i < 10; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = FindFastest(ctx, &opts)
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	for i := 0; i < 10; i++ {
		if errs[i] != nil {
			t.Errorf("Concurrent FindFastest[%d]: %v", i, errs[i])
		}
	}

	t.Logf("10 concurrent FindFastest (cached): %s", elapsed)
	if elapsed > 100*time.Millisecond {
		t.Errorf("Concurrent cached calls too slow: %s", elapsed)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
