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
		if targets[i].asn != "" {
			t.Errorf("target[%d] asn = %q, want empty", i, targets[i].asn)
		}
	}
}

func TestASNIndex(t *testing.T) {
	x := newASNIndex()
	x.add(netip.MustParsePrefix("10.0.0.0/8"), "AS1")
	x.add(netip.MustParsePrefix("10.1.0.0/16"), "AS2")

	tests := []struct {
		ip      string
		wantASN string
		wantOK  bool
	}{
		{ip: "10.1.2.3", wantASN: "AS2", wantOK: true}, // most specific match
		{ip: "10.2.3.4", wantASN: "AS1", wantOK: true}, // supernet match
		{ip: "11.0.0.1", wantASN: "", wantOK: false},   // no match
	}
	for _, tt := range tests {
		asn, ok := x.lookup(netip.MustParseAddr(tt.ip))
		if ok != tt.wantOK || asn != tt.wantASN {
			t.Errorf("lookup(%s) = (%q, %v), want (%q, %v)", tt.ip, asn, ok, tt.wantASN, tt.wantOK)
		}
	}
}

func TestResultASNMarshaling(t *testing.T) {
	unknown, err := json.Marshal(Result{IP: "192.0.2.1", Prefix: "192.0.2.1/32", PTR: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unknown), `"asn":null`) {
		t.Errorf("unknown ASN marshaled as %s, want \"asn\":null", unknown)
	}

	asn := "AS15169"
	known, err := json.Marshal(Result{IP: "8.8.8.8", Prefix: "8.8.8.8/32", ASN: &asn, PTR: []string{"dns.google"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(known), `"asn":"AS15169"`) {
		t.Errorf("known ASN marshaled as %s, want \"asn\":\"AS15169\"", known)
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
