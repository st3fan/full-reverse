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
