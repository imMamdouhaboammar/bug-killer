package procmap

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aegis/orchestrator/ledger"
)

type ProcessMapper struct{}

func NewProcessMapper() *ProcessMapper {
	return &ProcessMapper{}
}

func (pm *ProcessMapper) ScanActiveProcesses() []ledger.RuntimeAsset {
	var assets []ledger.RuntimeAsset

	// 1. Try Linux /proc filesystem first
	if _, err := os.Stat("/proc"); err == nil {
		procAssets := pm.scanLinuxProc()
		if len(procAssets) > 0 {
			return procAssets
		}
	}

	// 2. Cross-platform fallback via ps
	out, err := exec.Command("ps", "-axo", "pid,command").Output()
	if err != nil {
		return assets
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "PID") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		pid, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}

		cmd := strings.Join(parts[1:], " ")
		baseCmd := filepath.Base(parts[1])

		if strings.Contains(baseCmd, "php") {
			assets = append(assets, ledger.RuntimeAsset{
				Type:          "php",
				Path:          parts[1],
				Source:        "process",
				AssociatedPID: pid,
				Metadata: map[string]string{
					"cmdline": cmd,
				},
			})
		} else if strings.Contains(baseCmd, "node") {
			assets = append(assets, ledger.RuntimeAsset{
				Type:          "node",
				Path:          parts[1],
				Source:        "process",
				AssociatedPID: pid,
				Metadata: map[string]string{
					"cmdline": cmd,
				},
			})
		} else if strings.Contains(baseCmd, "bun") {
			assets = append(assets, ledger.RuntimeAsset{
				Type:          "bun",
				Path:          parts[1],
				Source:        "process",
				AssociatedPID: pid,
				Metadata: map[string]string{
					"cmdline": cmd,
				},
			})
		} else if strings.Contains(baseCmd, "nginx") || strings.Contains(baseCmd, "httpd") || strings.Contains(baseCmd, "apache2") {
			assets = append(assets, ledger.RuntimeAsset{
				Type:          "webserver",
				Path:          parts[1],
				Source:        "process",
				AssociatedPID: pid,
				Metadata: map[string]string{
					"cmdline": cmd,
					"server":  baseCmd,
				},
			})
		}
	}

	return assets
}

func (pm *ProcessMapper) scanLinuxProc() []ledger.RuntimeAsset {
	var assets []ledger.RuntimeAsset
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return assets
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			continue
		}

		cmdlineBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		cmdline := string(bytes.ReplaceAll(cmdlineBytes, []byte{0}, []byte(" ")))
		base := filepath.Base(exePath)

		if strings.Contains(base, "php") {
			assets = append(assets, ledger.RuntimeAsset{
				Type:          "php",
				Path:          exePath,
				Source:        "process",
				AssociatedPID: pid,
				Metadata: map[string]string{
					"cmdline": cmdline,
				},
			})
		} else if strings.Contains(base, "node") {
			assets = append(assets, ledger.RuntimeAsset{
				Type:          "node",
				Path:          exePath,
				Source:        "process",
				AssociatedPID: pid,
				Metadata: map[string]string{
					"cmdline": cmdline,
				},
			})
		}
	}

	return assets
}
