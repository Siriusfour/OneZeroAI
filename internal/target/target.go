package target

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

func ExpandCIDR(cidr string) ([]net.IP, error) {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("invalid cidr %q: %w", cidr, err)
	}
	base := ip.To4()
	if base == nil {
		return nil, fmt.Errorf("only ipv4 cidr is supported: %q", cidr)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only ipv4 cidr is supported: %q", cidr)
	}
	if ones > 30 {
		return []net.IP{base.Mask(network.Mask)}, nil
	}
	var out []net.IP
	for current := incIP(base.Mask(network.Mask)); network.Contains(current); current = incIP(current) {
		cp := make(net.IP, len(current))
		copy(cp, current)
		out = append(out, cp)
	}
	if len(out) >= 2 {
		out = out[:len(out)-1]
	}
	return out, nil
}

func ParsePorts(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	seen := map[int]struct{}{}
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		if strings.Contains(token, "-") {
			bounds := strings.Split(token, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range %q", token)
			}
			start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid range start %q: %w", token, err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid range end %q: %w", token, err)
			}
			if start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range %q", token)
			}
			for i := start; i <= end; i++ {
				seen[i] = struct{}{}
			}
			continue
		}
		port, err := strconv.Atoi(token)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", token)
		}
		seen[port] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no valid ports provided")
	}
	result := make([]int, 0, len(seen))
	for p := range seen {
		result = append(result, p)
	}
	sort.Ints(result)
	return result, nil
}

func incIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}
