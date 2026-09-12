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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the announced-prefixes endpoint of the RIPE Stat API.
const DefaultBaseURL = "https://stat.ripe.net/data/announced-prefixes/data.json"

// DefaultPrefixOverviewURL is the prefix-overview endpoint of the RIPE Stat API.
const DefaultPrefixOverviewURL = "https://stat.ripe.net/data/prefix-overview/data.json"

// DefaultASOverviewURL is the as-overview endpoint of the RIPE Stat API.
const DefaultASOverviewURL = "https://stat.ripe.net/data/as-overview/data.json"

// DefaultSearchURL is the searchcomplete endpoint of the RIPE Stat API.
const DefaultSearchURL = "https://stat.ripe.net/data/searchcomplete/data.json"

// DefaultCacheTTL is how long fetched responses are reused from the cache.
const DefaultCacheTTL = time.Hour

// Client queries the RIPE Stat data API.
type Client struct {
	// HTTPClient is used for requests. When nil, a client with a 30s timeout
	// is used.
	HTTPClient *http.Client
	// BaseURL overrides the API endpoint. When empty, DefaultBaseURL is used.
	BaseURL string
	// PrefixOverviewURL overrides the prefix-overview endpoint. When empty,
	// DefaultPrefixOverviewURL is used.
	PrefixOverviewURL string
	// ASOverviewURL overrides the as-overview endpoint. When empty,
	// DefaultASOverviewURL is used.
	ASOverviewURL string
	// SearchURL overrides the searchcomplete endpoint. When empty,
	// DefaultSearchURL is used.
	SearchURL string
	// CacheDir is where fetched responses are stored. When empty, caching is
	// disabled.
	CacheDir string
	// CacheTTL is the maximum age of a cached response. When zero, caching is
	// disabled.
	CacheTTL time.Duration
	// Logf, when set, receives human-readable messages about cache use and API
	// requests. It may be called concurrently.
	Logf func(format string, args ...any)
}

// logf forwards a message to the optional Logf hook.
func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// New returns a Client with sensible defaults, including a cache under
// $XDG_CACHE_HOME/full-reverse/ripestat (or ~/.cache/full-reverse/ripestat).
func New() *Client {
	return &Client{
		HTTPClient:        &http.Client{Timeout: 30 * time.Second},
		PrefixOverviewURL: DefaultPrefixOverviewURL,
		ASOverviewURL:     DefaultASOverviewURL,
		SearchURL:         DefaultSearchURL,
		CacheDir:          DefaultCacheDir(),
		CacheTTL:          DefaultCacheTTL,
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
			c.logf("RIPE Stat: using cached announced-prefixes for %s", resource)
			return prefixes, nil
		}
	}

	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}

	endpoint := base + "?resource=" + resource
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("ripestat: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	c.logf("Fetching %s", endpoint)
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

// ASInfo holds an AS name and organization, split from a RIPE Stat "holder"
// value of the form "<as-name> - <organization>".
type ASInfo struct {
	Name string
	Org  string
}

// splitHolder splits a RIPE Stat holder string on the first " - ".
func splitHolder(holder string) ASInfo {
	if i := strings.Index(holder, " - "); i >= 0 {
		return ASInfo{
			Name: strings.TrimSpace(holder[:i]),
			Org:  strings.TrimSpace(holder[i+3:]),
		}
	}
	return ASInfo{Name: strings.TrimSpace(holder)}
}

// PrefixOverview describes the RIPE Stat prefix-overview for an IP or prefix.
type PrefixOverview struct {
	// Prefix is the covering prefix reported by RIPE Stat, if any.
	Prefix netip.Prefix
	// ASN is the first announcing AS number, or 0 when unknown.
	ASN uint32
	// ASName is the as-name of the first announcing AS, or empty.
	ASName string
	// ASOrg is the organization of the first announcing AS, or empty.
	ASOrg string
	// Announced reports whether the prefix is currently announced.
	Announced bool
}

type prefixOverviewResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status_code"`
	Data       struct {
		Resource  string `json:"resource"`
		Announced bool   `json:"announced"`
		ASNs      []struct {
			ASN    uint32 `json:"asn"`
			Holder string `json:"holder"`
		} `json:"asns"`
	} `json:"data"`
}

// PrefixOverview asks RIPE Stat which prefix and ASN cover resource (an IP or a
// prefix). It uses the prefix-overview data API. A cached response younger than
// CacheTTL is reused when caching is enabled.
func (c *Client) PrefixOverview(ctx context.Context, resource string) (*PrefixOverview, error) {
	cacheKey := overviewCacheKey(resource)
	if body, ok := c.readCache(cacheKey); ok {
		if overview, err := parsePrefixOverview(body); err == nil {
			c.logf("using cached prefix-overview for %s", resource)
			return overview, nil
		}
	}

	base := c.PrefixOverviewURL
	if base == "" {
		base = DefaultPrefixOverviewURL
	}

	endpoint := base + "?resource=" + url.QueryEscape(resource)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("ripestat: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	c.logf("Fetching %s", endpoint)
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

	overview, err := parsePrefixOverview(body)
	if err != nil {
		return nil, err
	}
	c.writeCache(cacheKey, body)
	return overview, nil
}

// parsePrefixOverview validates a prefix-overview response body.
func parsePrefixOverview(body []byte) (*PrefixOverview, error) {
	var payload prefixOverviewResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("ripestat: decoding response: %w", err)
	}
	if payload.Status != "ok" {
		return nil, fmt.Errorf("ripestat: API status %q (HTTP %d)", payload.Status, payload.StatusCode)
	}

	overview := &PrefixOverview{Announced: payload.Data.Announced}
	if p, err := netip.ParsePrefix(payload.Data.Resource); err == nil && p.Addr().Is4() {
		overview.Prefix = p.Masked()
	}
	if len(payload.Data.ASNs) > 0 {
		overview.ASN = payload.Data.ASNs[0].ASN
		info := splitHolder(payload.Data.ASNs[0].Holder)
		overview.ASName = info.Name
		overview.ASOrg = info.Org
	}
	return overview, nil
}

type asOverviewResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status_code"`
	Data       struct {
		Holder string `json:"holder"`
	} `json:"data"`
}

// ASOverview returns the as-name and organization of an ASN. It uses the
// as-overview data API and reuses a cached response when caching is enabled.
func (c *Client) ASOverview(ctx context.Context, asn string) (ASInfo, error) {
	resource, err := NormalizeASN(asn)
	if err != nil {
		return ASInfo{}, err
	}

	cacheKey := asOverviewCacheKey(resource)
	if body, ok := c.readCache(cacheKey); ok {
		if info, err := parseASOverview(body); err == nil {
			c.logf("using cached AS overview for %s", resource)
			return info, nil
		}
	}

	base := c.ASOverviewURL
	if base == "" {
		base = DefaultASOverviewURL
	}

	endpoint := base + "?resource=" + url.QueryEscape(resource)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ASInfo{}, fmt.Errorf("ripestat: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	c.logf("Fetching %s", endpoint)
	resp, err := httpClient.Do(req)
	if err != nil {
		return ASInfo{}, fmt.Errorf("ripestat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ASInfo{}, fmt.Errorf("ripestat: unexpected HTTP status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ASInfo{}, fmt.Errorf("ripestat: reading response: %w", err)
	}

	info, err := parseASOverview(body)
	if err != nil {
		return ASInfo{}, err
	}
	c.writeCache(cacheKey, body)
	return info, nil
}

// parseASOverview validates an as-overview response body and returns the split
// as-name and organization.
func parseASOverview(body []byte) (ASInfo, error) {
	var payload asOverviewResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return ASInfo{}, fmt.Errorf("ripestat: decoding response: %w", err)
	}
	if payload.Status != "ok" {
		return ASInfo{}, fmt.Errorf("ripestat: API status %q (HTTP %d)", payload.Status, payload.StatusCode)
	}
	return splitHolder(payload.Data.Holder), nil
}

// asOverviewCacheKey returns the cache key for an as-overview resource.
func asOverviewCacheKey(asn string) string {
	return filepath.Join("as-overview", asn)
}

// ASMatch is one ASN suggestion returned by the RIPE Stat search API.
type ASMatch struct {
	// ASN is the AS number, e.g. 14618.
	ASN uint32
	// Name is the as-name portion of the description (the part before " - ").
	Name string
	// Org is the organization portion of the description, if present.
	Org string
	// Description is the full description, e.g. "AMAZON-AES - Amazon.com, Inc.".
	Description string
}

type searchResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status_code"`
	Data       struct {
		Categories []struct {
			Category    string `json:"category"`
			Suggestions []struct {
				Value       string `json:"value"`
				Description string `json:"description"`
			} `json:"suggestions"`
		} `json:"categories"`
	} `json:"data"`
}

// SearchASNs resolves an AS name (for example "AMAZON-AES") to candidate ASNs
// using the searchcomplete API. The response is cached when caching is enabled.
func (c *Client) SearchASNs(ctx context.Context, query string) ([]ASMatch, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("ripestat: empty search query")
	}

	cacheKey := searchCacheKey(query)
	if body, ok := c.readCache(cacheKey); ok {
		if matches, err := parseSearchASNs(body); err == nil {
			c.logf("using cached AS search for %s", query)
			return matches, nil
		}
	}

	base := c.SearchURL
	if base == "" {
		base = DefaultSearchURL
	}

	endpoint := base + "?resource=" + url.QueryEscape(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("ripestat: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	c.logf("Fetching %s", endpoint)
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

	matches, err := parseSearchASNs(body)
	if err != nil {
		return nil, err
	}
	c.writeCache(cacheKey, body)
	return matches, nil
}

// parseSearchASNs extracts ASN matches from a searchcomplete response body.
func parseSearchASNs(body []byte) ([]ASMatch, error) {
	var payload searchResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("ripestat: decoding response: %w", err)
	}
	if payload.Status != "ok" {
		return nil, fmt.Errorf("ripestat: API status %q (HTTP %d)", payload.Status, payload.StatusCode)
	}

	seen := make(map[uint32]struct{})
	var matches []ASMatch
	for _, category := range payload.Data.Categories {
		if !strings.EqualFold(category.Category, "ASNs") {
			continue
		}
		for _, s := range category.Suggestions {
			n, err := ASNNumber(s.Value)
			if err != nil {
				continue
			}
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}

			name := splitHolder(s.Description)
			matches = append(matches, ASMatch{
				ASN:         n,
				Name:        name.Name,
				Org:         name.Org,
				Description: s.Description,
			})
		}
	}
	return matches, nil
}

// searchCacheKey returns the cache key for a searchcomplete query.
func searchCacheKey(query string) string {
	key := strings.NewReplacer("/", "_", ":", "_", "\\", "_", " ", "_").Replace(strings.ToUpper(query))
	return filepath.Join("search", key)
}

// overviewCacheKey returns the cache key for a prefix-overview resource,
// namespaced in an "overview" subdirectory so it cannot collide with the
// AS<number>.json announced-prefixes files.
func overviewCacheKey(resource string) string {
	key := strings.NewReplacer("/", "_", ":", "_", "\\", "_").Replace(resource)
	return filepath.Join("overview", key)
}

// CachedPrefixASNs reads every cached announced-prefixes response and returns a
// map from prefix to the announcing AS number. It is best-effort: unreadable or
// malformed cache files are skipped. An empty map is returned when caching is
// disabled or the cache directory does not exist.
func (c *Client) CachedPrefixASNs() map[netip.Prefix]uint32 {
	result := make(map[netip.Prefix]uint32)
	if c.CacheDir == "" {
		return result
	}

	entries, err := os.ReadDir(c.CacheDir)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "AS") || !strings.HasSuffix(name, ".json") {
			continue
		}
		asn, err := ASNNumber(strings.TrimSuffix(name, ".json"))
		if err != nil {
			continue
		}

		body, err := os.ReadFile(filepath.Join(c.CacheDir, name))
		if err != nil {
			continue
		}
		prefixes, err := parseAnnouncedPrefixes(body)
		if err != nil {
			continue
		}
		for _, p := range prefixes {
			if _, exists := result[p]; !exists {
				result[p] = asn
			}
		}
	}
	return result
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

	tmp, err := os.CreateTemp(dir, "*.tmp")
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

// ASNNumber returns the numeric value of an ASN given as "AS15169", "as15169",
// or "15169".
func ASNNumber(asn string) (uint32, error) {
	canonical, err := NormalizeASN(asn)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(canonical[2:], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("ripestat: invalid ASN %q", asn)
	}
	return uint32(n), nil
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
