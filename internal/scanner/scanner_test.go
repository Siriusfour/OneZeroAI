package scanner

import (
	"testing"

	"onezeroai-mdns-cli/internal/model"
)

func TestMergeResult(t *testing.T) {
	a := model.ScanResult{
		IP:   "192.168.1.23",
		Host: "slw-nas.local",
		Service: []model.ServiceAsset{
			{Port: 5000, Proto: "tcp", Service: "http", Name: "slw-nas", Hostname: "slw-nas.local"},
		},
		Answers: model.AnswerSet{
			PTR: []string{"_http._tcp.local"},
		},
	}
	b := model.ScanResult{
		IP:   "192.168.1.23",
		Host: "slw-nas.local",
		Service: []model.ServiceAsset{
			{Port: 445, Proto: "tcp", Service: "smb", Name: "slw-nas", Hostname: "slw-nas.local"},
		},
		Answers: model.AnswerSet{
			PTR: []string{"_smb._tcp.local"},
		},
	}
	merged := mergeResult(a, b)
	if len(merged.Service) != 2 {
		t.Fatalf("expected 2 services, got %d", len(merged.Service))
	}
	if len(merged.Answers.PTR) != 2 {
		t.Fatalf("expected 2 ptr answers, got %d", len(merged.Answers.PTR))
	}
}
