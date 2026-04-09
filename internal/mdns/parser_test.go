package mdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParseMessageDeepBanner(t *testing.T) {
	msg := &dns.Msg{}
	msg.Answer = []dns.RR{
		&dns.PTR{
			Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
			Ptr: "_workstation._tcp.local.",
		},
		&dns.PTR{
			Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
			Ptr: "_qdiscover._tcp.local.",
		},
		&dns.SRV{
			Hdr:    dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
			Target: "slw-nas.local.",
			Port:   5000,
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
			Txt: []string{
				"accessType=https",
				"accessPort=86",
				"model=TS-X64",
				"displayModel=TS-464C",
				"fwVer=5.2.9",
				"fwBuildNum=20260214",
			},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
			A:   []byte{192, 168, 1, 23},
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 10},
			AAAA: []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x24, 0x5e, 0xbe, 0xff, 0xfe, 0x69, 0xa3, 0x13},
		},
	}

	result := ParseMessage(msg, "192.168.1.23", map[int]struct{}{5000: {}}, "192.168.1.23")
	if len(result.Service) != 1 {
		t.Fatalf("expected 1 service, got %d", len(result.Service))
	}
	svc := result.Service[0]
	if svc.Service != "qdiscover" {
		t.Fatalf("unexpected service: %s", svc.Service)
	}
	if svc.Meta["model"] != "TS-X64" {
		t.Fatalf("missing model meta")
	}
	if !strings.Contains(result.Banner, "fwBuildNum=20260214") {
		t.Fatalf("banner should include fwBuildNum, got:\n%s", result.Banner)
	}
	if len(result.Answers.PTR) != 2 {
		t.Fatalf("expected ptr list size 2, got %d", len(result.Answers.PTR))
	}
}
