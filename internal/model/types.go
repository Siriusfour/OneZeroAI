package model

type ScanResult struct {
	Target  string         `json:"target"`
	IP      string         `json:"ip"`
	Host    string         `json:"host"`
	Banner  string         `json:"banner"`
	Service []ServiceAsset `json:"services"`
	Answers AnswerSet      `json:"answers"`
}

type AnswerSet struct {
	PTR []string `json:"PTR"`
}

type ServiceAsset struct {
	Port     int               `json:"port"`
	Proto    string            `json:"proto"`
	Service  string            `json:"service"`
	Name     string            `json:"Name"`
	IPv4     string            `json:"IPv4"`
	IPv6     string            `json:"IPv6"`
	Hostname string            `json:"Hostname"`
	TTL      uint32            `json:"TTL"`
	Meta     map[string]string `json:"meta"`
}
