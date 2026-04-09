package mdns

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"onezeroai-mdns-cli/internal/model"
)

type serviceEntry struct {
	ServiceType  string
	InstanceFQDN string
	Name         string
	Hostname     string
	Port         int
	TTL          uint32
	IPv4         string
	IPv6         string
	TXT          map[string]string
}

func ParseMessage(msg *dns.Msg, fallbackIP string, filterPorts map[int]struct{}, target string) model.ScanResult {
	entries := map[string]*serviceEntry{}
	hostA := map[string]string{}
	hostAAAA := map[string]string{}
	ptrSet := map[string]struct{}{}

	records := append([]dns.RR{}, msg.Answer...)
	records = append(records, msg.Extra...)

	for _, rr := range records {
		switch v := rr.(type) {
		case *dns.PTR:
			ptrSet[strings.TrimSuffix(v.Ptr, ".")] = struct{}{}
			ensureEntry(entries, v.Ptr).ServiceType = extractServiceType(v.Hdr.Name)
			ensureEntry(entries, v.Ptr).TTL = v.Hdr.Ttl
		case *dns.SRV:
			entry := ensureEntry(entries, v.Hdr.Name)
			entry.Hostname = strings.TrimSuffix(v.Target, ".")
			entry.Port = int(v.Port)
			entry.TTL = v.Hdr.Ttl
			entry.Name = extractInstanceName(v.Hdr.Name)
			if entry.ServiceType == "" {
				entry.ServiceType = extractServiceType(v.Hdr.Name)
			}
		case *dns.TXT:
			entry := ensureEntry(entries, v.Hdr.Name)
			entry.TTL = v.Hdr.Ttl
			if entry.Name == "" {
				entry.Name = extractInstanceName(v.Hdr.Name)
			}
			if entry.ServiceType == "" {
				entry.ServiceType = extractServiceType(v.Hdr.Name)
			}
			if entry.TXT == nil {
				entry.TXT = map[string]string{}
			}
			for _, item := range v.Txt {
				k, val, ok := strings.Cut(item, "=")
				if !ok {
					entry.TXT[item] = "true"
					continue
				}
				entry.TXT[k] = val
			}
		case *dns.A:
			hostA[strings.TrimSuffix(v.Hdr.Name, ".")] = v.A.String()
		case *dns.AAAA:
			hostAAAA[strings.TrimSuffix(v.Hdr.Name, ".")] = v.AAAA.String()
		}
	}

	result := model.ScanResult{
		Target: target,
		IP:     fallbackIP,
		Host:   "",
		Answers: model.AnswerSet{
			PTR: sortedSet(ptrSet),
		},
	}

	for _, entry := range entries {
		if entry.Port == 0 && entry.Hostname == "" && len(entry.TXT) == 0 {
			continue
		}
		if entry.Port != 0 {
			if len(filterPorts) > 0 {
				if _, ok := filterPorts[entry.Port]; !ok {
					continue
				}
			}
		}
		if entry.Hostname != "" {
			if v, ok := hostA[entry.Hostname]; ok {
				entry.IPv4 = v
			}
			if v, ok := hostAAAA[entry.Hostname]; ok {
				entry.IPv6 = v
			}
		}
		if entry.IPv4 != "" {
			result.IP = entry.IPv4
		}
		if result.Host == "" && entry.Hostname != "" {
			result.Host = entry.Hostname
		}
		service := model.ServiceAsset{
			Port:     entry.Port,
			Proto:    "tcp",
			Service:  normalizeService(entry.ServiceType),
			Name:     entry.Name,
			IPv4:     entry.IPv4,
			IPv6:     entry.IPv6,
			Hostname: entry.Hostname,
			TTL:      entry.TTL,
			Meta:     map[string]string{},
		}
		for k, v := range entry.TXT {
			service.Meta[k] = v
		}
		result.Service = append(result.Service, service)
	}

	sort.Slice(result.Service, func(i, j int) bool {
		if result.Service[i].Port == result.Service[j].Port {
			return result.Service[i].Service < result.Service[j].Service
		}
		return result.Service[i].Port < result.Service[j].Port
	})
	result.Banner = BuildDeepBanner(result)
	return result
}

func BuildDeepBanner(result model.ScanResult) string {
	var lines []string
	for _, svc := range result.Service {
		lines = append(lines, fmt.Sprintf("%d/%s %s", svc.Port, svc.Proto, svc.Service))
		lines = append(lines, "Name="+svc.Name)
		if svc.IPv4 != "" {
			lines = append(lines, "IPv4="+svc.IPv4)
		}
		if svc.IPv6 != "" {
			lines = append(lines, "IPv6="+svc.IPv6)
		}
		if svc.Hostname != "" {
			lines = append(lines, "Hostname="+svc.Hostname)
		}
		lines = append(lines, "TTL="+strconv.FormatUint(uint64(svc.TTL), 10))
		if len(svc.Meta) > 0 {
			keys := make([]string, 0, len(svc.Meta))
			for k := range svc.Meta {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var kv []string
			for _, k := range keys {
				kv = append(kv, k+"="+svc.Meta[k])
			}
			lines = append(lines, strings.Join(kv, ","))
		}
	}
	if len(result.Answers.PTR) > 0 {
		lines = append(lines, "PTR="+strings.Join(result.Answers.PTR, ";"))
	}
	return strings.Join(lines, "\n")
}

func ensureEntry(entries map[string]*serviceEntry, fqdn string) *serviceEntry {
	key := strings.TrimSuffix(fqdn, ".")
	entry, ok := entries[key]
	if !ok {
		entry = &serviceEntry{InstanceFQDN: key, TXT: map[string]string{}}
		entries[key] = entry
	}
	return entry
}

func extractServiceType(fqdn string) string {
	name := strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(name, ".")
	if len(parts) < 3 {
		return ""
	}
	for i := 0; i < len(parts)-1; i++ {
		if strings.HasPrefix(parts[i], "_") && i+1 < len(parts) && strings.HasPrefix(parts[i+1], "_") {
			return strings.Join(parts[i:], ".")
		}
	}
	return ""
}

func extractInstanceName(fqdn string) string {
	name := strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(name, ".")
	for i := 0; i < len(parts)-1; i++ {
		if strings.HasPrefix(parts[i], "_") {
			return strings.Join(parts[:i], ".")
		}
	}
	return name
}

func normalizeService(serviceType string) string {
	if serviceType == "" {
		return "unknown"
	}
	parts := strings.Split(serviceType, ".")
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.TrimPrefix(parts[0], "_")
}

func sortedSet(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
