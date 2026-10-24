package supervisor

import (
	"fmt"
	"os/exec"
)

type ProcessSupervisor struct{}

func NewProcessSupervisor() *ProcessSupervisor {
	return &ProcessSupervisor{}
}

func (ps *ProcessSupervisor) ReloadService(serviceName string, dryRun bool) (string, error) {
	if dryRun {
		return fmt.Sprintf("[DRY-RUN] Would reload service '%s'", serviceName), nil
	}

	// 1. Try systemctl
	if _, err := exec.LookPath("systemctl"); err == nil {
		out, err := exec.Command("systemctl", "reload-or-restart", serviceName).CombinedOutput()
		if err == nil {
			return string(out), nil
		}
	}

	// 2. Try brew services on macOS
	if _, err := exec.LookPath("brew"); err == nil {
		out, err := exec.Command("brew", "services", "restart", serviceName).CombinedOutput()
		if err == nil {
			return string(out), nil
		}
	}

	return "", fmt.Errorf("unable to restart service '%s': no supported init system found", serviceName)
}

func (ps *ProcessSupervisor) RestartDockerContainer(containerID string, dryRun bool) (string, error) {
	if dryRun {
		return fmt.Sprintf("[DRY-RUN] Would restart Docker container '%s'", containerID), nil
	}

	out, err := exec.Command("docker", "restart", containerID).CombinedOutput()
	return string(out), err
}
