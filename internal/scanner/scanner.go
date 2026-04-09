package scanner

import (
	"net"
	"strconv"
	"sync"
	"time"

	"onezeroai-mdns-cli/internal/mdns"
	"onezeroai-mdns-cli/internal/model"
)

type Config struct {
	Workers int
	Timeout time.Duration
	Retries int
}

type targetPort struct {
	IP   net.IP
	Port int
}

func Scan(ips []net.IP, ports []int, cfg Config) []model.ScanResult {
	if cfg.Workers <= 0 {
		cfg.Workers = 32
	}
	jobs := make(chan targetPort)
	results := make(chan model.ScanResult, len(ips)*len(ports))
	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				result, err := mdns.ProbeTarget(job.IP, job.Port, mdns.ProbeConfig{
					Timeout: cfg.Timeout,
					Retries: cfg.Retries,
				})
				if err != nil || len(result.Service) == 0 {
					continue
				}
				results <- result
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			for _, port := range ports {
				jobs <- targetPort{IP: ip, Port: port}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	merged := map[string]model.ScanResult{}
	for result := range results {
		key := result.IP + "|" + result.Host
		current, ok := merged[key]
		if !ok {
			merged[key] = result
			continue
		}
		merged[key] = mergeResult(current, result)
	}

	output := make([]model.ScanResult, 0, len(merged))
	for _, item := range merged {
		item.Banner = mdns.BuildDeepBanner(item)
		output = append(output, item)
	}
	return output
}

func mergeResult(a, b model.ScanResult) model.ScanResult {
	seenService := map[string]struct{}{}
	for _, svc := range a.Service {
		seenService[serviceKey(svc)] = struct{}{}
	}
	for _, svc := range b.Service {
		key := serviceKey(svc)
		if _, ok := seenService[key]; ok {
			continue
		}
		a.Service = append(a.Service, svc)
		seenService[key] = struct{}{}
	}
	ptrSet := map[string]struct{}{}
	for _, p := range a.Answers.PTR {
		ptrSet[p] = struct{}{}
	}
	for _, p := range b.Answers.PTR {
		if _, ok := ptrSet[p]; ok {
			continue
		}
		a.Answers.PTR = append(a.Answers.PTR, p)
		ptrSet[p] = struct{}{}
	}
	return a
}

func serviceKey(s model.ServiceAsset) string {
	return s.Service + "|" + s.Name + "|" + s.Hostname + "|" + s.IPv4 + "|" + s.IPv6 + "|" + strconv.Itoa(s.Port)
}
