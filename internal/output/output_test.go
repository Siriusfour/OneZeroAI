package output

import (
	"bytes"
	"strings"
	"testing"

	"onezeroai-mdns-cli/internal/model"
)

func TestWriteJSONL(t *testing.T) {
	results := []model.ScanResult{
		{
			Host: "slw-nas.local",
			IP:   "192.168.1.23",
			Service: []model.ServiceAsset{
				{
					Port:    5000,
					Proto:   "tcp",
					Service: "qdiscover",
					Name:    "slw-nas",
					TTL:     10,
					Meta: map[string]string{
						"model": "TS-X64",
					},
				},
			},
			Answers: model.AnswerSet{PTR: []string{"_qdiscover._tcp.local"}},
		},
	}
	var b bytes.Buffer
	if err := Write(results, "jsonl", &b); err != nil {
		t.Fatalf("Write jsonl failed: %v", err)
	}
	if !strings.Contains(b.String(), "\"qdiscover\"") {
		t.Fatalf("unexpected output: %s", b.String())
	}
}

func TestWriteTable(t *testing.T) {
	results := []model.ScanResult{
		{
			Host: "slw-nas.local",
			IP:   "192.168.1.23",
			Service: []model.ServiceAsset{
				{
					Port:    5000,
					Proto:   "tcp",
					Service: "qdiscover",
					Name:    "slw-nas",
					TTL:     10,
					Meta: map[string]string{
						"fwVer": "5.2.9",
					},
				},
			},
			Answers: model.AnswerSet{PTR: []string{"_qdiscover._tcp.local"}},
		},
	}
	var b bytes.Buffer
	if err := Write(results, "table", &b); err != nil {
		t.Fatalf("Write table failed: %v", err)
	}
	if !strings.Contains(b.String(), "meta=fwVer=5.2.9") {
		t.Fatalf("table missing meta: %s", b.String())
	}
}
