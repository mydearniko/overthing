package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mydearniko/overthing/pkg/relay"
)

// discoverRelayFromShortlist fetches a server-maintained shortlist of healthy
// relays (one relay:// URI per line, refreshed server-side on a timer) and
// probes only those entries through the provided dialer. This keeps selection
// fast through a VLESS/REALITY tunnel (a handful of handshakes instead of
// hundreds) while still tracking relay churn: the shortlist is regenerated
// regularly on the server.
func discoverRelayFromShortlist(
	ctx context.Context,
	shortlistURL string,
	logger func(level, msg string),
	dialer func(context.Context, string, string) (net.Conn, error),
	filter func(relay.Relay) bool,
) (string, error) {
	uris, err := fetchShortlist(ctx, shortlistURL, dialer)
	if err != nil {
		return "", err
	}
	if logger != nil {
		logger("info", fmt.Sprintf("Probing %d shortlisted relays...", len(uris)))
	}

	// Probe sequentially with a tight timeout: the shortlist is ordered
	// best-first (server measured RTT from its own vantage), so the first
	// reachable relay is essentially always the right pick. A sequential
	// scan of 18 entries at ~100-300ms each is far cheaper than probing the
	// full pool through the tunnel, and avoids handshake storms.
	for _, uri := range uris {
		if filter != nil {
			r, err := relay.ParseURL(uri)
			if err != nil {
				continue
			}
			if !filter(*r) {
				continue
			}
		}
		addr, id, err := parseRelayURI(uri)
		if err != nil {
			continue
		}
		ok := probeRelayReachable(ctx, addr, dialer)
		if ok {
			if logger != nil {
				logger("ok", fmt.Sprintf("Selected relay (shortlist): %s", addr))
			}
			return "relay://" + addr + "/?id=" + id, nil
		}
	}
	return "", fmt.Errorf("no shortlisted relay reachable (%d tried)", len(uris))
}

// fetchShortlist downloads the list, returning one relay:// URI per line.
func fetchShortlist(ctx context.Context, url string, dialer func(context.Context, string, string) (net.Conn, error)) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	transport := &http.Transport{
		DisableKeepAlives: true,
	}
	if dialer != nil {
		transport.DialContext = dialer
	}
	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shortlist fetch: %s", resp.Status)
	}

	var uris []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "relay://") {
			continue
		}
		uris = append(uris, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(uris) == 0 {
		return nil, fmt.Errorf("shortlist empty")
	}
	return uris, nil
}

// probeRelayReachable performs a quick TCP connect (through the tunnel, which
// means a full outer TLS+VLESS handshake) to check the relay accepts joins.
func probeRelayReachable(ctx context.Context, addr string, dialer func(context.Context, string, string) (net.Conn, error)) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	var conn net.Conn
	var err error
	if dialer != nil {
		conn, err = dialer(probeCtx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{Timeout: 4 * time.Second}).DialContext(probeCtx, "tcp", addr)
	}
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
