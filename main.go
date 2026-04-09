package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"onezeroai-mdns-cli/internal/output"
	"onezeroai-mdns-cli/internal/scanner"
	"onezeroai-mdns-cli/internal/target"
)

func main() {
	var (
		cidrs      string
		ports      string
		format     string
		workers    int
		timeoutSec int
		retries    int
	)
	flag.StringVar(&cidrs, "cidr", "", "CIDR list, separated by comma")
	flag.StringVar(&ports, "ports", "5353", "Port list, supports ranges like 5353,5000-5002")
	flag.StringVar(&format, "format", "json", "Output format: json|jsonl|table")
	flag.IntVar(&workers, "workers", 64, "Concurrent workers")
	flag.IntVar(&timeoutSec, "timeout", 2, "Timeout in seconds")
	flag.IntVar(&retries, "retries", 1, "Retry count")
	flag.Parse()

	if strings.TrimSpace(cidrs) == "" {
		exitErr(fmt.Errorf("missing required flag: --cidr"))
	}
	ipTargets, err := parseCIDRs(cidrs)
	if err != nil {
		exitErr(err)
	}
	portTargets, err := target.ParsePorts(ports)
	if err != nil {
		exitErr(err)
	}

	results := scanner.Scan(ipTargets, portTargets, scanner.Config{
		Workers: workers,
		Timeout: time.Duration(timeoutSec) * time.Second,
		Retries: retries,
	})
	if err := output.Write(results, format, os.Stdout); err != nil {
		exitErr(err)
	}
}

func parseCIDRs(raw string) ([]net.IP, error) {
	parts := strings.Split(raw, ",")
	seen := map[string]struct{}{}
	var all []net.IP
	for _, part := range parts {
		cidr := strings.TrimSpace(part)
		if cidr == "" {
			continue
		}
		ips, err := target.ExpandCIDR(cidr)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			all = append(all, ip)
		}
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no ip targets generated")
	}
	return all, nil
}

func exitErr(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
