package docker

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestDockerInspectorIsolationAudit(t *testing.T) {
	mockJSON := `{
		"Id": "c1234567890abcdef",
		"Name": "/vulnerable-prod-app",
		"Image": "php:8.2-fpm",
		"Config": {
			"Env": ["APP_ENV=production", "SECRET_KEY=leaked_key"]
		},
		"HostConfig": {
			"Privileged": true,
			"ReadonlyRootfs": false,
			"CapAdd": ["SYS_ADMIN"],
			"NetworkMode": "host",
			"PidMode": "host"
		},
		"RootFS": {
			"Type": "layers",
			"Layers": ["sha256:layer1", "sha256:layer2"]
		}
	}`

	mockClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(mockJSON)),
				Header:     make(http.Header),
			}
		}),
	}

	inspector := NewDockerInspectorWithClient("/dummy.sock", mockClient)
	profile, err := inspector.InspectContainerIsolation("c1234567890abcdef")
	if err != nil {
		t.Fatalf("unexpected error inspecting container isolation: %v", err)
	}

	if !profile.Privileged {
		t.Errorf("expected Privileged=true")
	}
	if len(profile.IsolationWarnings) < 4 {
		t.Errorf("expected multiple isolation warnings, got %d", len(profile.IsolationWarnings))
	}
	if profile.VulnerabilityScore < 80 {
		t.Errorf("expected VulnerabilityScore >= 80 for fully unconfined container, got %d", profile.VulnerabilityScore)
	}
	if len(profile.ImageLayers) != 2 {
		t.Errorf("expected 2 image layers, got %d", len(profile.ImageLayers))
	}
}
