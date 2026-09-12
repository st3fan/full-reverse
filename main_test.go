package main

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/st3fan/full-reverse/ripestat"
)

func TestResolveTargets(t *testing.T) {
	targets, err := resolveTargets(context.Background(), ripestat.New(), []string{"1.1.1.1", "10.0.0.7/24"})
	if err != nil {
		t.Fatalf("resolveTargets: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("1.1.1.1/32"),
		netip.MustParsePrefix("10.0.0.0/24"),
	}
	if len(targets) != len(want) {
		t.Fatalf("got %d targets, want %d", len(targets), len(want))
	}
	for i := range want {
		if targets[i].prefix != want[i] {
			t.Errorf("target[%d] prefix = %v, want %v", i, targets[i].prefix, want[i])
		}
		if targets[i].asn != 0 {
			t.Errorf("target[%d] asn = %d, want 0", i, targets[i].asn)
		}
	}
}

func TestASNIndex(t *testing.T) {
	x := newASNIndex()
	x.add(netip.MustParsePrefix("10.0.0.0/8"), 1)
	x.add(netip.MustParsePrefix("10.1.0.0/16"), 2)

	tests := []struct {
		ip      string
		wantASN uint32
		wantOK  bool
	}{
		{ip: "10.1.2.3", wantASN: 2, wantOK: true},  // most specific match
		{ip: "10.2.3.4", wantASN: 1, wantOK: true},  // supernet match
		{ip: "11.0.0.1", wantASN: 0, wantOK: false}, // no match
	}
	for _, tt := range tests {
		asn, _, ok := x.lookup(netip.MustParseAddr(tt.ip))
		if ok != tt.wantOK || asn != tt.wantASN {
			t.Errorf("lookup(%s) = (%d, %v), want (%d, %v)", tt.ip, asn, ok, tt.wantASN, tt.wantOK)
		}
	}
}

func TestResultASNMarshaling(t *testing.T) {
	unknown, err := json.Marshal(Result{IP: "192.0.2.1", Target: "192.0.2.1", PTR: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unknown), `"prefix":null`) || !strings.Contains(string(unknown), `"asn":null`) || !strings.Contains(string(unknown), `"as_name":null`) || !strings.Contains(string(unknown), `"as_org":null`) {
		t.Errorf("unknown AS marshaled as %s, want null prefix, asn, as_name and as_org", unknown)
	}

	asn := uint32(15169)
	name := "GOOGLE"
	org := "Google LLC"
	prefix := "8.8.8.0/24"
	known, err := json.Marshal(Result{IP: "8.8.8.8", Target: "8.8.8.8", Prefix: &prefix, ASN: &asn, ASName: &name, ASOrg: &org, PTR: []string{"dns.google"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(known), `"target":"8.8.8.8"`) {
		t.Errorf("target not found in %s", known)
	}
	if !strings.Contains(string(known), `"prefix":"8.8.8.0/24"`) {
		t.Errorf("prefix not found in %s", known)
	}
	if !strings.Contains(string(known), `"asn":15169`) {
		t.Errorf("known ASN marshaled as %s, want \"asn\":15169", known)
	}
	if !strings.Contains(string(known), `"as_name":"GOOGLE"`) {
		t.Errorf("known AS name not found in %s", known)
	}
	if !strings.Contains(string(known), `"as_org":"Google LLC"`) {
		t.Errorf("known AS org not found in %s", known)
	}
}

func TestPickASN(t *testing.T) {
	matches := []ripestat.ASMatch{
		{ASN: 14618, Name: "AMAZON-AES"},
		{ASN: 16509, Name: "AMAZON-02"},
	}

	m, err := pickASN("AMAZON-AES", matches)
	if err != nil || m.ASN != 14618 {
		t.Errorf("pickASN(AMAZON-AES) = %+v, %v; want AS14618", m, err)
	}

	m, err = pickASN("amazon-aes", matches)
	if err != nil || m.ASN != 14618 {
		t.Errorf("pickASN(amazon-aes) = %+v, %v; want AS14618", m, err)
	}

	m, err = pickASN("anything", []ripestat.ASMatch{{ASN: 1, Name: "X"}})
	if err != nil || m.ASN != 1 {
		t.Errorf("pickASN single = %+v, %v; want AS1", m, err)
	}

	if _, err := pickASN("GOOGLE", []ripestat.ASMatch{{ASN: 1, Name: "GOOGLE"}, {ASN: 2, Name: "GOOGLE"}}); err == nil {
		t.Error("pickASN ambiguous exact: expected error")
	}
	if _, err := pickASN("X", []ripestat.ASMatch{{ASN: 1, Name: "A"}, {ASN: 2, Name: "B"}}); err == nil {
		t.Error("pickASN ambiguous fuzzy: expected error")
	}
}

func TestPTRNames(t *testing.T) {
	resp := new(dns.Msg)
	resp.Answer = []dns.RR{
		&dns.PTR{Ptr: "mail.example.com."},
		&dns.A{A: net.ParseIP("192.0.2.10").To4()},
		&dns.PTR{Ptr: "other.example.com."},
	}

	got := ptrNames(resp)
	want := []string{"mail.example.com", "other.example.com"}
	if len(got) != len(want) {
		t.Fatalf("ptrNames = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ptrNames[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestARecords(t *testing.T) {
	resp := new(dns.Msg)
	resp.Answer = []dns.RR{
		&dns.A{A: net.ParseIP("192.0.2.10").To4()},
		&dns.PTR{Ptr: "ignored.example.com."},
		&dns.A{A: net.ParseIP("192.0.2.11").To4()},
	}

	got := aRecords(resp)
	want := []netip.Addr{
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("192.0.2.11"),
	}
	if len(got) != len(want) {
		t.Fatalf("aRecords = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("aRecords[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}
