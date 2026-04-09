package main

import "testing"

func TestParseCIDRs(t *testing.T) {
	ips, err := parseCIDRs("192.168.1.0/30,192.168.1.2/32")
	if err != nil {
		t.Fatalf("parseCIDRs failed: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 unique ips, got %d", len(ips))
	}
}
