package main

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestResolveTargets(t *testing.T) {
	targets, err := resolveTargets(context.Background(), []string{"1.1.1.1", "10.0.0.7/24"})
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
