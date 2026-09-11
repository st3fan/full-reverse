// Package ripestat provides a minimal client for the RIPE Stat data API.
//
// See https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes.
package ripestat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the announced-prefixes endpoint of the RIPE Stat API.
const DefaultBaseURL = "https://stat.ripe.net/data/announced-prefixes/data.json"

// DefaultCacheTTL is how long fetched responses are reused from the cache.
const DefaultCacheTTL = time.Hour

// Client queries the RIPE Stat data API.
type Client struct {
	// HTTPClient is used for requests. When nil, a client with a 30s timeout
	// is used.
	HTTPClient *http.Client
	// BaseURL overrides the API endpoint. When empty, DefaultBaseURL is used.
	BaseURL string
	// CacheDir is where fetched responses are stored. When empty, caching is
	// disabled.
	CacheDir string
	// CacheTTL is the maximum age of a cached response. When zero, caching is
	// disabled.
	CacheTTL time.Duration
}

// New returns a Client with sensible defaults, including a cache under
// $XDG_CACHE_HOME/full-reverse/ripestat (or ~/.cache/full-reverse/ripestat).
func New() *Client {
	return &Client{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		CacheDir:   DefaultCacheDir(),
		CacheTTL:   DefaultCacheTTL,
	}
}

// DefaultCacheDir returns the platform cache directory for ripestat data, or an
// empty string when it cannot be determined.
func DefaultCacheDir() string {
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, "full-reverse", "ripestat")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cache", "full-reverse", "ripestat")
}

type announcedPrefixesResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status_code"`
	Data       struct {
		Resource string `json:"resource"`
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

// AnnouncedPrefixes returns the deduplicated IPv4 prefixes currently announced
// by asn. IPv6 prefixes and malformed entries are ignored. A cached response
// younger than CacheTTL is reused when caching is enabled.
func (c *Client) AnnouncedPrefixes(ctx context.Context, asn string) ([]netip.Prefix, error) {
	resource, err := NormalizeASN(asn)
	if err != nil {
		return nil, err
	}

	if body, ok := c.readCache(resource); ok {
		if prefixes, err := parseAnnouncedPrefixes(body); err == nil {
			return prefixes, nil
		}
	}

	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?resource="+resource, nil)
	if err != nil {
		return nil, fmt.Errorf("ripestat: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ripestat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ripestat: unexpected HTTP status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ripestat: reading response: %w", err)
	}

	prefixes, err := parseAnnouncedPrefixes(body)
	if err != nil {
		return nil, err
	}
	c.writeCache(resource, body)
	return prefixes, nil
}

// parseAnnouncedPrefixes validates an announced-prefixes response body and
// extracts its IPv4 prefixes.
func parseAnnouncedPrefixes(body []byte) ([]netip.Prefix, error) {
	var payload announcedPrefixesResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("ripestat: decoding response: %w", err)
	}
	if payload.Status != "ok" {
		return nil, fmt.Errorf("ripestat: API status %q (HTTP %d)", payload.Status, payload.StatusCode)
	}

	prefixes := make([]netip.Prefix, 0, len(payload.Data.Prefixes))
	seen := make(map[netip.Prefix]struct{}, len(payload.Data.Prefixes))
	for _, entry := range payload.Data.Prefixes {
		p, err := netip.ParsePrefix(entry.Prefix)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// cachePath returns the cache file for resource, or an empty string when
// caching is disabled.
func (c *Client) cachePath(resource string) string {
	if c.CacheDir == "" || c.CacheTTL <= 0 {
		return ""
	}
	return filepath.Join(c.CacheDir, resource+".json")
}

// readCache returns a cached response body if one exists and is still fresh.
func (c *Client) readCache(resource string) ([]byte, bool) {
	path := c.cachePath(resource)
	if path == "" {
		return nil, false
	}
	info, err := os.Stat(path)
	if err != nil || time.Since(info.ModTime()) > c.CacheTTL {
		return nil, false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return body, true
}

// writeCache stores a response body in the cache. Failures are ignored; the
// cache is best-effort.
func (c *Client) writeCache(resource string, body []byte) {
	path := c.cachePath(resource)
	if path == "" {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}

	tmp, err := os.CreateTemp(dir, resource+".*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // best-effort cleanup; a no-op after rename

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	os.Rename(tmpName, path)
}

// NormalizeASN validates asn and returns it in canonical "AS<number>" form.
// Both "15169" and "as15169" are accepted.
func NormalizeASN(asn string) (string, error) {
	s := strings.TrimSpace(asn)
	if len(s) >= 2 && strings.EqualFold(s[:2], "AS") {
		s = s[2:]
	}
	if s == "" {
		return "", fmt.Errorf("ripestat: empty ASN")
	}
	if _, err := strconv.ParseUint(s, 10, 32); err != nil {
		return "", fmt.Errorf("ripestat: invalid ASN %q", asn)
	}
	return "AS" + s, nil
}
