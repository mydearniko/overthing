package network

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const androidDNSDialTimeout = 2 * time.Second

var bootstrapDNSServers = []string{
	"1.1.1.1",
	"8.8.8.8",
	"2606:4700:4700::1111",
	"2001:4860:4860::8888",
}

var (
	defaultResolverOnce sync.Once
	defaultResolver     *net.Resolver

	androidDNSServersOnce sync.Once
	androidDNSServers     []string
)

// NewDialer returns the default dialer used by overthing.
// On Android/Termux we override Go's resolver when it points at a dead
// localhost DNS listener (for example [::1]:53), which breaks relay discovery.
func NewDialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if resolver := resolverForPlatform(); resolver != nil {
		d.Resolver = resolver
	}
	return d
}

// NewBootstrapDialer returns a dialer that always uses public DNS servers
// instead of the system resolver. The resolver list includes any valid
// addresses from OVERTHING_DNS plus the built-in public bootstrap resolvers.
func NewBootstrapDialer(timeout time.Duration) *net.Dialer {
	return NewDNSDialer(timeout, BootstrapDNSServers())
}

// BootstrapDNSServers returns the full DNS server set used for discovery
// fallback. User-supplied OVERTHING_DNS servers are tried first, then the
// built-in public resolvers are appended as extra attempts.
func BootstrapDNSServers() []string {
	servers := parseDNSServerList(os.Getenv("OVERTHING_DNS"))
	for _, server := range bootstrapDNSServers {
		servers = appendDNSServer(servers, server)
	}
	return servers
}

// NewDNSDialer returns a dialer that resolves names via the supplied DNS
// server list. Invalid, duplicate, loopback, and unspecified values are ignored.
// When the supplied list is empty after normalization it falls back to the
// bootstrap resolver set.
func NewDNSDialer(timeout time.Duration, servers []string) *net.Dialer {
	resolverServers := normalizeDNSServers(servers)
	if len(resolverServers) == 0 {
		resolverServers = BootstrapDNSServers()
	}

	return &net.Dialer{
		Timeout:  timeout,
		Resolver: resolverWithServers(resolverServers),
	}
}

// LookupIP mirrors net.DefaultResolver.LookupIP but uses the Android override
// when available.
func LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if resolver := resolverForPlatform(); resolver != nil {
		return resolver.LookupIP(ctx, "ip", host)
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func resolverForPlatform() *net.Resolver {
	if !platformLooksAndroid(
		runtime.GOOS,
		os.Getenv("TERMUX_VERSION"),
		os.Getenv("PREFIX"),
		os.Getenv("ANDROID_ROOT"),
		os.Getenv("ANDROID_DATA"),
	) {
		return nil
	}

	defaultResolverOnce.Do(func() {
		servers := androidResolverServers()
		if len(servers) == 0 {
			return
		}

		defaultResolver = resolverWithServers(servers)
	})

	return defaultResolver
}

func androidResolverServers() []string {
	androidDNSServersOnce.Do(func() {
		androidDNSServers = discoverAndroidDNSServers()
	})

	if len(androidDNSServers) == 0 {
		return nil
	}

	servers := make([]string, len(androidDNSServers))
	copy(servers, androidDNSServers)
	return servers
}

func discoverAndroidDNSServers() []string {
	return BootstrapDNSServers()
}

func parseDNSServerList(value string) []string {
	var servers []string

	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	}) {
		servers = appendDNSServer(servers, part)
	}

	return servers
}

func normalizeDNSServers(values []string) []string {
	var servers []string
	for _, value := range values {
		servers = appendDNSServer(servers, value)
	}
	return servers
}

func appendDNSServer(servers []string, raw string) []string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return servers
	}

	normalized := ip.String()
	for _, server := range servers {
		if server == normalized {
			return servers
		}
	}

	return append(servers, normalized)
}

func resolverWithServers(servers []string) *net.Resolver {
	servers = normalizeDNSServers(servers)
	if len(servers) == 0 {
		return nil
	}

	var serverIndex uint32

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			server := servers[int(atomic.AddUint32(&serverIndex, 1)-1)%len(servers)]
			return (&net.Dialer{Timeout: androidDNSDialTimeout}).DialContext(
				ctx,
				resolverDialNetwork(network),
				net.JoinHostPort(server, "53"),
			)
		},
	}
}

func resolverDialNetwork(network string) string {
	if strings.HasPrefix(network, "udp") || strings.HasPrefix(network, "tcp") {
		return network
	}
	return "udp"
}

func platformLooksAndroid(goos string, termuxVersion string, prefix string, androidRoot string, androidData string) bool {
	if goos == "android" {
		return true
	}
	if termuxVersion != "" {
		return true
	}
	if strings.Contains(prefix, "com.termux") {
		return true
	}
	return androidRoot != "" || androidData != ""
}
