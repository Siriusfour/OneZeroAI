package target

import "testing"

func TestExpandCIDR(t *testing.T) {
	ips, err := ExpandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("ExpandCIDR failed: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 ips, got %d", len(ips))
	}
	if got := ips[0].String(); got != "192.168.1.1" {
		t.Fatalf("unexpected first ip: %s", got)
	}
	if got := ips[1].String(); got != "192.168.1.2" {
		t.Fatalf("unexpected second ip: %s", got)
	}
}

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("9,445,5000-5001,5353")
	if err != nil {
		t.Fatalf("ParsePorts failed: %v", err)
	}
	want := []int{9, 445, 5000, 5001, 5353}
	if len(ports) != len(want) {
		t.Fatalf("unexpected len, got=%d want=%d", len(ports), len(want))
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports[%d]=%d want=%d", i, ports[i], want[i])
		}
	}
}

func TestParsePortsInvalid(t *testing.T) {
	if _, err := ParsePorts("0,70000"); err == nil {
		t.Fatalf("expected error for invalid ports")
	}
}
