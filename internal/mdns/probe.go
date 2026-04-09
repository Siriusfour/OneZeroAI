package mdns

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"onezeroai-mdns-cli/internal/model"
)

type ProbeConfig struct {
	Timeout time.Duration
	Retries int
}

func ProbeTarget(ip net.IP, port int, cfg ProbeConfig) (model.ScanResult, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 1
	}
	addr := &net.UDPAddr{IP: ip, Port: port}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return model.ScanResult{}, fmt.Errorf("dial udp %s: %w", addr.String(), err)
	}
	defer conn.Close()

	query := buildDiscoveryQuery()
	payload, err := query.Pack()
	if err != nil {
		return model.ScanResult{}, fmt.Errorf("pack mdns query: %w", err)
	}
	filter := map[int]struct{}{port: {}}
	var lastErr error
	for i := 0; i < cfg.Retries; i++ {
		if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
			return model.ScanResult{}, fmt.Errorf("set deadline: %w", err)
		}
		if _, err := conn.Write(payload); err != nil {
			lastErr = err
			continue
		}
		buf := make([]byte, 65535)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			lastErr = err
			continue
		}
		resp := &dns.Msg{}
		if err := resp.Unpack(buf[:n]); err != nil {
			lastErr = err
			continue
		}
		return ParseMessage(resp, ip.String(), filter, ip.String()), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no mdns response")
	}
	return model.ScanResult{}, lastErr
}

func buildDiscoveryQuery() *dns.Msg {
	msg := &dns.Msg{}
	msg.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	msg.RecursionDesired = false
	msg.Question = append(msg.Question, dns.Question{Name: "_workstation._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET})
	msg.Question = append(msg.Question, dns.Question{Name: "_http._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET})
	msg.Question = append(msg.Question, dns.Question{Name: "_smb._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET})
	msg.Question = append(msg.Question, dns.Question{Name: "_qdiscover._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET})
	msg.Question = append(msg.Question, dns.Question{Name: "_device-info._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET})
	msg.Question = append(msg.Question, dns.Question{Name: "_afpovertcp._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET})
	return msg
}
