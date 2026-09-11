package main

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

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
