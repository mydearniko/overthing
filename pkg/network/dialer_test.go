package network

import (
	"reflect"
	"testing"
)

func TestParseDNSServerListExtractsUsableDNSServers(t *testing.T) {
	t.Parallel()

	value := "127.0.0.1,8.8.8.8 2001:4860:4860::8888;8.8.8.8 ::1 dns.google"

	got := parseDNSServerList(value)
	want := []string{"8.8.8.8", "2001:4860:4860::8888"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected DNS servers: got %v want %v", got, want)
	}
}

func TestAppendDNSServerFiltersInvalidValues(t *testing.T) {
	t.Parallel()

	var servers []string
	for _, value := range []string{"", "not-an-ip", "127.0.0.1", "::1", "8.8.4.4", "8.8.4.4"} {
		servers = appendDNSServer(servers, value)
	}

	want := []string{"8.8.4.4"}
	if !reflect.DeepEqual(servers, want) {
		t.Fatalf("unexpected filtered DNS servers: got %v want %v", servers, want)
	}
}

func TestPlatformLooksAndroid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		goos          string
		termuxVersion string
		prefix        string
		androidRoot   string
		androidData   string
		want          bool
	}{
		{name: "android runtime", goos: "android", want: true},
		{name: "termux env", goos: "linux", termuxVersion: "0.118.0", want: true},
		{name: "termux prefix", goos: "linux", prefix: "/data/data/com.termux/files/usr", want: true},
		{name: "android env", goos: "linux", androidRoot: "/system", want: true},
		{name: "android data env", goos: "linux", androidData: "/data", want: true},
		{name: "plain linux", goos: "linux", want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := platformLooksAndroid(tt.goos, tt.termuxVersion, tt.prefix, tt.androidRoot, tt.androidData); got != tt.want {
				t.Fatalf("platformLooksAndroid() = %v, want %v", got, tt.want)
			}
		})
	}
}
