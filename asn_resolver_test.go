package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/st3fan/full-reverse/ripestat"
)

// Disable the disk cache so request counts exercise the resolver's memory cache.
func testASNResolver(t *testing.T, handler http.HandlerFunc) *asnResolver {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &asnResolver{
		client: &ripestat.Client{
			HTTPClient: server.Client(), PrefixOverviewURL: server.URL,
			ASOverviewURL: server.URL,
		},
		index: newASNIndex(),
	}
}

func checkUnknownASN(t *testing.T, r *asnResolver, ip string) {
	t.Helper()
	asn, info, prefix := r.resolve(context.Background(), netip.MustParseAddr(ip))
	if asn != 0 || info != (ripestat.ASInfo{}) || prefix.IsValid() {
		t.Errorf("resolve(%s) = (%d, %+v, %v), want unknown metadata", ip, asn, info, prefix)
	}
}

func TestASNResolverUnknownCacheScope(t *testing.T) {
	for _, tt := range []struct {
		name, resource string
		wantCalls      int64
	}{
		{"covering prefix", "192.0.2.7/24", 2},
		{"missing prefix", "", 3},
		{"plain IP", "192.0.2.1", 3},
		{"invalid prefix", "invalid", 3},
		{"non-covering prefix", "203.0.113.0/24", 3},
		{"IPv6 prefix", "2001:db8::/32", 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int64
			r := testASNResolver(t, func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				fmt.Fprintf(w, `{"status":"ok","data":{"resource":%q,"announced":false,"asns":[]}}`, tt.resource)
			})
			for _, ip := range []string{"192.0.2.1", "192.0.2.1", "192.0.2.2", "198.51.100.1"} {
				checkUnknownASN(t, r, ip)
			}
			if got := calls.Load(); got != tt.wantCalls {
				t.Errorf("API calls = %d, want %d", got, tt.wantCalls)
			}
		})
	}
}

func TestASNResolverKnownOverridesUnknown(t *testing.T) {
	var calls atomic.Int64
	r := testASNResolver(t, func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, `{"status":"ok","data":{"resource":"192.0.2.0/24","asns":[]}}`)
	})
	checkUnknownASN(t, r, "192.0.2.1")
	prefix := netip.MustParsePrefix("192.0.2.128/25")
	r.index.add(prefix, 64500)
	info := ripestat.ASInfo{Name: "EXAMPLE", Org: "Example"}
	r.names = map[uint32]ripestat.ASInfo{64500: info}
	asn, gotInfo, gotPrefix := r.resolve(context.Background(), netip.MustParseAddr("192.0.2.129"))
	if asn != 64500 || gotInfo != info || gotPrefix != prefix {
		t.Fatalf("known result = (%d, %+v, %v)", asn, gotInfo, gotPrefix)
	}
	checkUnknownASN(t, r, "192.0.2.2")
	if calls.Load() != 1 {
		t.Fatalf("API calls = %d, want 1", calls.Load())
	}
}

func TestASNResolverUnknownConcurrent(t *testing.T) {
	var calls atomic.Int64
	r := testASNResolver(t, func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, `{"status":"ok","data":{"resource":"192.0.2.0/24","asns":[]}}`)
	})
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 1; i <= 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			checkUnknownASN(t, r, fmt.Sprintf("192.0.2.%d", i))
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("API calls = %d, want 1", calls.Load())
	}
}

func TestASNResolverErrorsAreRetried(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		status     int
	}{
		{"HTTP error", "unavailable", http.StatusServiceUnavailable},
		{"API error", `{"status":"error"}`, http.StatusOK},
		{"decode error", `{`, http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int64
			r := testASNResolver(t, func(w http.ResponseWriter, req *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(tt.status)
					fmt.Fprint(w, tt.body)
					return
				}
				fmt.Fprint(w, `{"status":"ok","data":{"resource":"192.0.2.0/24","asns":[{"asn":64500,"holder":"EXAMPLE - Example"}]}}`)
			})
			checkUnknownASN(t, r, "192.0.2.1")
			for range 2 {
				asn, info, prefix := r.resolve(context.Background(), netip.MustParseAddr("192.0.2.1"))
				if asn != 64500 || info.Name != "EXAMPLE" || prefix.String() != "192.0.2.0/24" {
					t.Fatalf("retry result = (%d, %+v, %v)", asn, info, prefix)
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("API calls = %d, want 2", calls.Load())
			}
		})
	}
}
