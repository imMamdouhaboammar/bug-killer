package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aegis/orchestrator/ledger"
)

// ContainerIsolationProfile encapsulates deep security audits of container boundaries.
type ContainerIsolationProfile struct {
	ContainerID        string            `json:"container_id"`
	ContainerName      string            `json:"container_name"`
	Image              string            `json:"image"`
	Privileged         bool              `json:"privileged"`
	ReadonlyRootfs     bool              `json:"readonly_rootfs"`
	CapAdd             []string          `json:"cap_add"`
	SecurityOpt        []string          `json:"security_opt"`
	NetworkMode        string            `json:"network_mode"`
	PidMode            string            `json:"pid_mode"`
	EnvironmentVars    []string          `json:"environment_vars"`
	ImageLayers        []string          `json:"image_layers"`
	IsolationWarnings  []string          `json:"isolation_warnings"`
	VulnerabilityScore int               `json:"vulnerability_score"`
}

type ContainerInspectionDetail struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"`
	Config struct {
		Env []string `json:"Env"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		CapAdd         []string `json:"CapAdd"`
		SecurityOpt    []string `json:"SecurityOpt"`
		NetworkMode    string   `json:"NetworkMode"`
		PidMode        string   `json:"PidMode"`
	} `json:"HostConfig"`
	RootFS struct {
		Type   string   `json:"Type"`
		Layers []string `json:"Layers"`
	} `json:"RootFS"`
}

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

// NewDockerInspectorWithClient is provided for deterministic unit testing with mock HTTP transports.
func NewDockerInspectorWithClient(socketPath string, client *http.Client) *DockerInspector {
	return &DockerInspector{
		socketPath: socketPath,
		client:     client,
	}
}

func (d *DockerInspector) InspectRunningContainers() []ledger.RuntimeAsset {
	var assets []ledger.RuntimeAsset

	req, err := http.NewRequest("GET", "http://localhost/containers/json", nil)
	if err != nil {
		return assets
	}

	resp, err := d.client.Do(req)
	if err != nil {
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

		shortID := c.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}

		assets = append(assets, ledger.RuntimeAsset{
			Type:    runtimeType,
			Path:    c.Image,
			Source:  "docker",
			Version: c.Image,
			Metadata: map[string]string{
				"container_id":   shortID,
				"container_name": name,
				"state":          c.State,
				"status":         c.Status,
			},
		})
	}

	return assets
}

// InspectContainerIsolation audits security parameters, environment leakages, and image layer boundaries.
func (d *DockerInspector) InspectContainerIsolation(containerID string) (*ContainerIsolationProfile, error) {
	url := fmt.Sprintf("http://localhost/containers/%s/json", containerID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker inspect request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query docker inspect endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker inspect failed with HTTP status %d", resp.StatusCode)
	}

	var detail ContainerInspectionDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, fmt.Errorf("failed to decode container inspect JSON: %w", err)
	}

	profile := &ContainerIsolationProfile{
		ContainerID:       detail.ID,
		ContainerName:     strings.TrimPrefix(detail.Name, "/"),
		Image:             detail.Image,
		Privileged:        detail.HostConfig.Privileged,
		ReadonlyRootfs:    detail.HostConfig.ReadonlyRootfs,
		CapAdd:            detail.HostConfig.CapAdd,
		SecurityOpt:       detail.HostConfig.SecurityOpt,
		NetworkMode:       detail.HostConfig.NetworkMode,
		PidMode:           detail.HostConfig.PidMode,
		EnvironmentVars:   detail.Config.Env,
		ImageLayers:       detail.RootFS.Layers,
		IsolationWarnings: make([]string, 0),
	}

	// Flag risky container isolation states
	if profile.Privileged {
		profile.IsolationWarnings = append(profile.IsolationWarnings, "CONTAINER_RUNS_PRIVILEGED: Full host device access granted")
		profile.VulnerabilityScore += 50
	}
	if !profile.ReadonlyRootfs {
		profile.IsolationWarnings = append(profile.IsolationWarnings, "ROOTFS_WRITABLE: Container filesystem is mutable at runtime")
		profile.VulnerabilityScore += 15
	}
	if profile.PidMode == "host" {
		profile.IsolationWarnings = append(profile.IsolationWarnings, "PID_HOST_SHARED: Container shares PID namespace with host")
		profile.VulnerabilityScore += 30
	}
	if profile.NetworkMode == "host" {
		profile.IsolationWarnings = append(profile.IsolationWarnings, "NETWORK_HOST_SHARED: Container bypasses network isolation")
		profile.VulnerabilityScore += 25
	}
	for _, cap := range profile.CapAdd {
		if cap == "SYS_ADMIN" || cap == "ALL" {
			profile.IsolationWarnings = append(profile.IsolationWarnings, fmt.Sprintf("DANGEROUS_CAPABILITY_GRANTED: %s", cap))
			profile.VulnerabilityScore += 35
		}
	}

	return profile, nil
}
