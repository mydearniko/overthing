package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TunnelDialer wraps an underlying dialer so that relay connections are
// carried inside an ordinary HTTPS/WebSocket session to a front endpoint.
// From the egress network's perspective the connection is a standard
// WebSocket (HTTP/1.1 upgrade over TLS) to a reputable host; the relay TLS
// handshake and bep-relay framing happen inside the tunnel.
//
// Front URI format:
//
//	wss://worker.example.workers.dev/?relay=<host>:<port>
//	(or simply wss://worker.example.workers.dev — the worker relays to any
//	 relay when the target is passed as a query parameter per-dial)
type TunnelDialer struct {
	// FrontURL is the WebSocket endpoint, e.g. wss://bridge.example.workers.dev
	FrontURL string

	// TLSClientConfig is used for the outer TLS connection to the front.
	// When nil, system defaults apply (real certificate verification).
	TLSClientConfig *tls.Config

	// Inner dialer used to reach the front endpoint itself (interface
	// binding etc). When nil, the standard dialer is used.
	Inner DialerFunc
}

// parseFront splits the front URL into host and base path.
func parseFront(frontURL string) (host, basePath string, useTLS bool, err error) {
	u, err := url.Parse(frontURL)
	if err != nil {
		return "", "", false, err
	}
	switch u.Scheme {
	case "wss", "https":
		useTLS = true
	case "ws", "http":
		useTLS = false
	default:
		return "", "", false, fmt.Errorf("unsupported front scheme: %s", u.Scheme)
	}
	if u.Host == "" {
		return "", "", false, fmt.Errorf("front URL missing host")
	}
	return u.Host, u.Path, useTLS, nil
}

// DialContext connects to the front endpoint and upgrades to a WebSocket,
// then returns the raw bidirectional stream for inner (relay) traffic.
// The addr parameter (relay host:port) is forwarded to the worker as the
// "relay" query parameter so one worker can serve any relay.
func (t *TunnelDialer) DialContext(ctx context.Context, network_, addr string) (net.Conn, error) {
	if network_ != "tcp" {
		return nil, fmt.Errorf("unsupported network: %s", network_)
	}

	frontHost, basePath, useTLS, err := parseFront(t.FrontURL)
	if err != nil {
		return nil, err
	}

	// Resolve and dial the front endpoint.
	var conn net.Conn
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if t.Inner != nil {
		conn, err = t.Inner(ctx, "tcp", frontHost)
	} else {
		// Default to port 443 for wss fronts.
		hostPort := frontHost
		if !strings.Contains(hostPort, ":") {
			if useTLS {
				hostPort = net.JoinHostPort(hostPort, "443")
			} else {
				hostPort = net.JoinHostPort(hostPort, "80")
			}
		}
		conn, err = dialer.DialContext(ctx, "tcp", hostPort)
	}
	if err != nil {
		return nil, fmt.Errorf("front dial failed: %w", err)
	}

	if useTLS {
		tlsConn := tls.Client(conn, t.TLSClientConfig)
		tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("front TLS handshake failed: %w", err)
		}
		tlsConn.SetDeadline(time.Time{})
		conn = tlsConn
	}

	// Build the WebSocket upgrade request. The relay target rides as a
	// query parameter so the worker knows where to connect.
	relayParam := base64.URLEncoding.EncodeToString([]byte(addr))
	path := basePath
	if path == "" {
		path = "/"
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	requestURI := path + sep + "relay=" + relayParam

	key := makeWSKey()
	req := "GET " + requestURI + " HTTP/1.1\r\n" +
		"Host: " + frontHost + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n" +
		"\r\n"

	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("front upgrade write failed: %w", err)
	}

	resp, err := http.ReadResponse(newBufReader(conn), nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("front upgrade read failed: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("front upgrade rejected: %s", resp.Status)
	}
	conn.SetDeadline(time.Time{})

	return newWSConn(conn), nil
}

// makeWSKey generates a random Sec-WebSocket-Key header value.
func makeWSKey() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return base64.StdEncoding.EncodeToString(buf)
}
