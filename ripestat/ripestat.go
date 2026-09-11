// Package ripestat provides a minimal client for the RIPE Stat data API.
//
// See https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes.
package ripestat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the announced-prefixes endpoint of the RIPE Stat API.
const DefaultBaseURL = "https://stat.ripe.net/data/announced-prefixes/data.json"

// Client queries the RIPE Stat data API.
type Client struct {
	// HTTPClient is used for requests. When nil, a client with a 30s timeout
	// is used.
	HTTPClient *http.Client
	// BaseURL overrides the API endpoint. When empty, DefaultBaseURL is used.
	BaseURL string
}

// New returns a Client with sensible defaults.
func New() *Client {
	return &Client{HTTPClient: &http.Client{Timeout: 30 * time.Second}}
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
// by asn. IPv6 prefixes and malformed entries are ignored.
func (c *Client) AnnouncedPrefixes(ctx context.Context, asn string) ([]netip.Prefix, error) {
	resource, err := NormalizeASN(asn)
	if err != nil {
		return nil, err
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

	var payload announcedPrefixesResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
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
