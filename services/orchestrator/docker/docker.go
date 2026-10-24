package docker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aegis/orchestrator/ledger"
)

type DockerInspector struct {
	socketPath string
	client     *http.Client
}

type ContainerSummary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	Command string            `json:"Command"`
	Labels  map[string]string `json:"Labels"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
}

func NewDockerInspector(socketPath string) *DockerInspector {
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	return &DockerInspector{
		socketPath: socketPath,
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
	}
}

func (d *DockerInspector) InspectRunningContainers() []ledger.RuntimeAsset {
	var assets []ledger.RuntimeAsset

	// Query Docker API v1.45 via unix socket
	req, err := http.NewRequest("GET", "http://localhost/containers/json", nil)
	if err != nil {
		return assets
	}

	resp, err := d.client.Do(req)
	if err != nil {
		// Docker daemon not running or socket inaccessible
		return assets
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return assets
	}

	var containers []ContainerSummary
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return assets
	}

	for _, c := range containers {
		imageLower := strings.ToLower(c.Image)
		runtimeType := "container"
		if strings.Contains(imageLower, "php") {
			runtimeType = "php"
		} else if strings.Contains(imageLower, "node") {
			runtimeType = "node"
		} else if strings.Contains(imageLower, "bun") {
			runtimeType = "bun"
		} else if strings.Contains(imageLower, "nginx") || strings.Contains(imageLower, "apache") {
			runtimeType = "webserver"
		}

		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		assets = append(assets, ledger.RuntimeAsset{
			Type:    runtimeType,
			Path:    c.Image,
			Source:  "docker",
			Version: c.Image,
			Metadata: map[string]string{
				"container_id":   c.ID[:12],
				"container_name": name,
				"state":          c.State,
				"status":         c.Status,
			},
		})
	}

	return assets
}
