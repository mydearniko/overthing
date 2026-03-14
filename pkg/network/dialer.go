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
	androidDNSIndex       uint32
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
// (1.1.1.1, 8.8.8.8) instead of the system resolver. This is useful in
// environments where the system DNS is broken, missing, or firewalled
// (containers, minimal VMs, restrictive networks).
func NewBootstrapDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:  timeout,
		Resolver: bootstrapResolver(),
	}
}

var (
	bootstrapResolverOnce sync.Once
	bootstrapResolverVal  *net.Resolver
	bootstrapDNSIndex     uint32
)

func bootstrapResolver() *net.Resolver {
	bootstrapResolverOnce.Do(func() {
		servers := make([]string, len(bootstrapDNSServers))
		copy(servers, bootstrapDNSServers)

		if custom := parseDNSServerList(os.Getenv("OVERTHING_DNS")); len(custom) > 0 {
			servers = custom
		}

		bootstrapResolverVal = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				server := servers[int(atomic.AddUint32(&bootstrapDNSIndex, 1)-1)%len(servers)]
				if !strings.HasPrefix(network, "udp") && !strings.HasPrefix(network, "tcp") {
					network = "udp"
				}
				return (&net.Dialer{Timeout: androidDNSDialTimeout}).DialContext(
					ctx,
					network,
					net.JoinHostPort(server, "53"),
				)
			},
		}
	})
	return bootstrapResolverVal
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

		defaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				server := servers[int(atomic.AddUint32(&androidDNSIndex, 1)-1)%len(servers)]
				if !strings.HasPrefix(network, "udp") && !strings.HasPrefix(network, "tcp") {
					network = "udp"
				}
				return (&net.Dialer{Timeout: androidDNSDialTimeout}).DialContext(
					ctx,
					network,
					net.JoinHostPort(server, "53"),
				)
			},
		}
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
	if servers := parseDNSServerList(os.Getenv("OVERTHING_DNS")); len(servers) > 0 {
		return servers
	}

	servers := make([]string, len(bootstrapDNSServers))
	copy(servers, bootstrapDNSServers)
	return servers
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
