package ledger

import (
	"encoding/json"
	"os"
	"time"
)

type RuntimeAsset struct {
	Type        string            `json:"type"` // "php", "node", "bun", "webserver", "container"
	Path        string            `json:"path"`
	Version     string            `json:"version,omitempty"`
	Source      string            `json:"source"` // "binary", "manifest", "docker", "process"
	Metadata    map[string]string `json:"metadata,omitempty"`
	AssociatedPID int             `json:"associated_pid,omitempty"`
}

type CoverageLedger struct {
	HostID       string         `json:"host_id"`
	GeneratedAt  string         `json:"generated_at"`
	ScanDuration string         `json:"scan_duration"`
	TotalAssets  int            `json:"total_assets"`
	Assets       []RuntimeAsset `json:"assets"`
}

func NewCoverageLedger(hostID string) *CoverageLedger {
	return &CoverageLedger{
		HostID:      hostID,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Assets:      make([]RuntimeAsset, 0),
	}
}

func (l *CoverageLedger) AddAsset(asset RuntimeAsset) {
	l.Assets = append(l.Assets, asset)
	l.TotalAssets = len(l.Assets)
}

func (l *CoverageLedger) WriteToFile(filePath string) error {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}
