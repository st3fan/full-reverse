package ripestat

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeASN(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "15169", want: "AS15169"},
		{in: "AS15169", want: "AS15169"},
		{in: "as15169", want: "AS15169"},
		{in: " As3333 ", want: "AS3333"},
		{in: "", wantErr: true},
		{in: "AS", wantErr: true},
		{in: "notanasn", wantErr: true},
		{in: "AS-1", wantErr: true},
	}

	for _, tt := range tests {
		got, err := NormalizeASN(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("NormalizeASN(%q) = %q, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeASN(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeASN(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAnnouncedPrefixes(t *testing.T) {
	const body = `{
	  "status": "ok",
	  "status_code": 200,
	  "data": {
	    "resource": "AS15169",
	    "prefixes": [
	      {"prefix": "8.8.8.0/24"},
	      {"prefix": "2001:4860::/32"},
	      {"prefix": "8.8.8.0/24"},
	      {"prefix": "not-a-prefix"},
	      {"prefix": "8.8.4.0/24"}
	    ]
	  }
	}`

	var gotResource string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotResource = r.URL.Query().Get("resource")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	defer server.Close()

	client := &Client{HTTPClient: server.Client(), BaseURL: server.URL}
	prefixes, err := client.AnnouncedPrefixes(context.Background(), "as15169")
	if err != nil {
		t.Fatalf("AnnouncedPrefixes: %v", err)
	}

	if gotResource != "AS15169" {
		t.Errorf("resource = %q, want %q", gotResource, "AS15169")
	}

	want := []netip.Prefix{
		netip.MustParsePrefix("8.8.8.0/24"),
		netip.MustParsePrefix("8.8.4.0/24"),
	}
	if len(prefixes) != len(want) {
		t.Fatalf("got %d prefixes %v, want %d", len(prefixes), prefixes, len(want))
	}
	for i := range want {
		if prefixes[i] != want[i] {
			t.Errorf("prefix[%d] = %v, want %v", i, prefixes[i], want[i])
		}
	}
}

func TestAnnouncedPrefixesErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"error","status_code":400,"data":{"prefixes":[]}}`)
	}))
	defer server.Close()

	client := &Client{HTTPClient: server.Client(), BaseURL: server.URL}
	if _, err := client.AnnouncedPrefixes(context.Background(), "15169"); err == nil {
		t.Fatal("AnnouncedPrefixes: expected error, got nil")
	}
}

func TestPrefixOverviewCache(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, `{"status":"ok","status_code":200,"data":{"resource":"8.8.8.0/24","announced":true,"asns":[{"asn":15169}]}}`)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	client := &Client{
		HTTPClient:        server.Client(),
		PrefixOverviewURL: server.URL,
		CacheDir:          cacheDir,
		CacheTTL:          time.Hour,
	}

	for i := 0; i < 3; i++ {
		ov, err := client.PrefixOverview(context.Background(), "8.8.8.8")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if ov.ASN != 15169 {
			t.Fatalf("call %d: asn = %d, want 15169", i, ov.ASN)
		}
	}

	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1 (cached)", got)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "overview", "8.8.8.8.json")); err != nil {
		t.Errorf("cache file missing: %v", err)
	}
}

func TestPrefixOverviewCacheExpired(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, `{"status":"ok","status_code":200,"data":{"resource":"8.8.8.0/24","announced":true,"asns":[{"asn":15169}]}}`)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	client := &Client{
		HTTPClient:        server.Client(),
		PrefixOverviewURL: server.URL,
		CacheDir:          cacheDir,
		CacheTTL:          time.Hour,
	}

	if _, err := client.PrefixOverview(context.Background(), "8.8.8.8"); err != nil {
		t.Fatalf("first call: %v", err)
	}

	path := filepath.Join(cacheDir, "overview", "8.8.8.8.json")
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("aging cache file: %v", err)
	}

	if _, err := client.PrefixOverview(context.Background(), "8.8.8.8"); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("server hits = %d, want 2 (expired cache)", got)
	}
}

func TestPrefixOverview(t *testing.T) {
	var gotResource string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotResource = r.URL.Query().Get("resource")
		io.WriteString(w, `{"status":"ok","status_code":200,"data":{"resource":"8.8.8.0/24","announced":true,"asns":[{"asn":15169,"holder":"GOOGLE - Google LLC"}]}}`)
	}))
	defer server.Close()

	client := &Client{HTTPClient: server.Client(), PrefixOverviewURL: server.URL}
	var logged []string
	client.Logf = func(format string, args ...any) { logged = append(logged, format) }
	ov, err := client.PrefixOverview(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("PrefixOverview: %v", err)
	}
	if len(logged) == 0 || logged[0] != "Fetching %s" {
		t.Errorf("Logf calls = %v, want a fetch URL message", logged)
	}
	if gotResource != "8.8.8.8" {
		t.Errorf("resource = %q, want %q", gotResource, "8.8.8.8")
	}
	if want := netip.MustParsePrefix("8.8.8.0/24"); ov.Prefix != want {
		t.Errorf("prefix = %v, want %v", ov.Prefix, want)
	}
	if ov.ASN != 15169 {
		t.Errorf("asn = %d, want 15169", ov.ASN)
	}
	if ov.ASName != "GOOGLE" {
		t.Errorf("as name = %q, want %q", ov.ASName, "GOOGLE")
	}
	if ov.ASOrg != "Google LLC" {
		t.Errorf("as org = %q, want %q", ov.ASOrg, "Google LLC")
	}
	if !ov.Announced {
		t.Error("announced = false, want true")
	}
}

func TestASNNumber(t *testing.T) {
	tests := []struct {
		in   string
		want uint32
	}{
		{in: "15169", want: 15169},
		{in: "AS15169", want: 15169},
		{in: "as3333", want: 3333},
	}
	for _, tt := range tests {
		got, err := ASNNumber(tt.in)
		if err != nil {
			t.Errorf("ASNNumber(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ASNNumber(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
	if _, err := ASNNumber("not-an-asn"); err == nil {
		t.Error("ASNNumber(\"not-an-asn\") = nil error, want error")
	}
}

func TestASOverview(t *testing.T) {
	var hits atomic.Int64
	var gotResource string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotResource = r.URL.Query().Get("resource")
		io.WriteString(w, `{"status":"ok","status_code":200,"data":{"holder":"GOOGLE - Google LLC"}}`)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	client := &Client{
		HTTPClient:    server.Client(),
		ASOverviewURL: server.URL,
		CacheDir:      cacheDir,
		CacheTTL:      time.Hour,
	}

	for i := 0; i < 2; i++ {
		info, err := client.ASOverview(context.Background(), "as15169")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if info.Name != "GOOGLE" || info.Org != "Google LLC" {
			t.Fatalf("call %d: info = %+v, want GOOGLE / Google LLC", i, info)
		}
	}
	if gotResource != "AS15169" {
		t.Errorf("resource = %q, want AS15169", gotResource)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1 (cached)", got)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "as-overview", "AS15169.json")); err != nil {
		t.Errorf("cache file missing: %v", err)
	}
}

func TestSearchASNs(t *testing.T) {
	var hits atomic.Int64
	var gotResource string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotResource = r.URL.Query().Get("resource")
		io.WriteString(w, `{"status":"ok","status_code":200,"data":{"categories":[{"category":"ASNs","suggestions":[{"label":"AS14618","value":"AS14618","description":"AMAZON-AES - Amazon.com, Inc."},{"value":"AS16509","description":"AMAZON-02 - Amazon.com, Inc."},{"value":"not-an-asn","description":"junk"}]},{"category":"Prefixes","suggestions":[{"value":"8.8.8.0/24","description":"ignored"}]}]}}`)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	client := &Client{
		HTTPClient: server.Client(),
		SearchURL:  server.URL,
		CacheDir:   cacheDir,
		CacheTTL:   time.Hour,
	}

	for i := 0; i < 2; i++ {
		matches, err := client.SearchASNs(context.Background(), "AMAZON-AES")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if len(matches) != 2 {
			t.Fatalf("call %d: got %d matches %v", i, len(matches), matches)
		}
		if matches[0].ASN != 14618 || matches[0].Name != "AMAZON-AES" || matches[0].Org != "Amazon.com, Inc." || matches[0].Description != "AMAZON-AES - Amazon.com, Inc." {
			t.Errorf("call %d: match[0] = %+v", i, matches[0])
		}
	}

	if gotResource != "AMAZON-AES" {
		t.Errorf("resource = %q, want AMAZON-AES", gotResource)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1 (cached)", got)
	}
}

func TestCachedPrefixASNs(t *testing.T) {
	dir := t.TempDir()
	body := `{"status":"ok","status_code":200,"data":{"prefixes":[{"prefix":"193.0.18.0/23"},{"prefix":"2001:db8::/32"}]}}`
	if err := os.WriteFile(filepath.Join(dir, "AS3333.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// An unparseable cache file and an unrelated file must be skipped.
	if err := os.WriteFile(filepath.Join(dir, "AS15169.json"), []byte(`{"status":"error"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := (&Client{CacheDir: dir}).CachedPrefixASNs()
	if len(got) != 1 {
		t.Fatalf("got %d entries %v, want 1", len(got), got)
	}
	want := netip.MustParsePrefix("193.0.18.0/23")
	if asn, ok := got[want]; !ok || asn != 3333 {
		t.Errorf("entry %v = %d, %v; want 3333", want, asn, ok)
	}
}

func TestAnnouncedPrefixesCache(t *testing.T) {
	const body = `{"status":"ok","status_code":200,"data":{"prefixes":[{"prefix":"8.8.8.0/24"}]}}`

	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, body)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	client := &Client{
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
		CacheDir:   cacheDir,
		CacheTTL:   time.Hour,
	}

	want := netip.MustParsePrefix("8.8.8.0/24")
	for i := 0; i < 3; i++ {
		prefixes, err := client.AnnouncedPrefixes(context.Background(), "15169")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if len(prefixes) != 1 || prefixes[0] != want {
			t.Fatalf("call %d: got %v, want [%v]", i, prefixes, want)
		}
	}

	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1 (cached)", got)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "AS15169.json")); err != nil {
		t.Errorf("cache file missing: %v", err)
	}
}

func TestAnnouncedPrefixesCacheExpired(t *testing.T) {
	const body = `{"status":"ok","status_code":200,"data":{"prefixes":[{"prefix":"8.8.8.0/24"}]}}`

	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, body)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	client := &Client{
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
		CacheDir:   cacheDir,
		CacheTTL:   time.Hour,
	}

	if _, err := client.AnnouncedPrefixes(context.Background(), "15169"); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Age the cache file beyond the TTL.
	path := filepath.Join(cacheDir, "AS15169.json")
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("aging cache file: %v", err)
	}

	if _, err := client.AnnouncedPrefixes(context.Background(), "15169"); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("server hits = %d, want 2 (expired cache)", got)
	}
}
