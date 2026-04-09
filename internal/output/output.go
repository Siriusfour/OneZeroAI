package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"onezeroai-mdns-cli/internal/model"
)

func Write(results []model.ScanResult, format string, w io.Writer) error {
	switch strings.ToLower(format) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	case "jsonl":
		enc := json.NewEncoder(w)
		for _, result := range results {
			if err := enc.Encode(result); err != nil {
				return err
			}
		}
		return nil
	case "table":
		for _, result := range results {
			if _, err := fmt.Fprintf(w, "Host=%s IP=%s\n", result.Host, result.IP); err != nil {
				return err
			}
			for _, svc := range result.Service {
				if _, err := fmt.Fprintf(w, "  %d/%s %s Name=%s TTL=%d\n", svc.Port, svc.Proto, svc.Service, svc.Name, svc.TTL); err != nil {
					return err
				}
				if len(svc.Meta) > 0 {
					if _, err := fmt.Fprintln(w, "    meta="+joinMeta(svc.Meta)); err != nil {
						return err
					}
				}
			}
			if _, err := fmt.Fprintln(w, "  PTR="+strings.Join(result.Answers.PTR, ",")); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func joinMeta(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(m))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}
