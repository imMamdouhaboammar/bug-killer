package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	omniv1 "github.com/aegis/healer/omniv1"
	"github.com/aegis/healer/pkgmgr"
	"github.com/aegis/healer/server"
	"github.com/aegis/healer/supervisor"
	"github.com/aegis/healer/waf"
	"google.golang.org/grpc"
)

type AuditFinding struct {
	FilePath           string `json:"file_path"`
	IsVulnerable       bool   `json:"is_vulnerable"`
	VulnerabilityID    string `json:"vulnerability_id"`
	Severity           string `json:"severity"`
	SafeThreshold      string `json:"safe_threshold"`
	ReachabilityStatus string `json:"reachability_status"`
}

type AuditReportInput struct {
	HostID         string         `json:"host_id"`
	BinaryFindings []AuditFinding `json:"binary_findings"`
}

func main() {
	udsSocket := flag.String("uds", "", "Start as UDS gRPC server on socket path (e.g. /tmp/omni_healer.sock)")
	backupDir := flag.String("backup-dir", "/tmp/.omni_backups", "Directory to store Ed25519 signed backups")
	findingsPath := flag.String("findings", "findings.json", "Path to findings.json from inspector")
	nginxConf := flag.String("nginx", "", "Path to Nginx config to inject virtual patch")
	haproxyConf := flag.String("haproxy", "", "Path to HAProxy config to inject guard")
	apacheConf := flag.String("apache", "", "Path to Apache config to inject guard")
	upgradeRuntime := flag.String("upgrade", "", "Upgrade runtime via package manager ('php', 'node', or 'npm')")
	reloadService := flag.String("reload", "", "Reload system service after patch ('nginx', 'php-fpm', etc.)")
	dryRun := flag.Bool("dry-run", false, "Preview actions without applying changes")
	flag.Parse()

	// 1. UDS gRPC Server Mode
	if *udsSocket != "" {
		_ = os.Remove(*udsSocket)
		lis, err := net.Listen("unix", *udsSocket)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to listen on UDS socket %s: %v\n", *udsSocket, err)
			os.Exit(1)
		}
		// Security hardening: enforce strict 0600 permissions on the privileged gRPC UDS socket
		_ = os.Chmod(*udsSocket, 0600)
		defer func() {
			lis.Close()
			_ = os.Remove(*udsSocket)
		}()

		healerSvc, err := server.NewStatefulHealerServer(*backupDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to initialize Healer Server: %v\n", err)
			os.Exit(1)
		}

		grpcServer := grpc.NewServer()
		omniv1.RegisterOmniStatefulHealerServer(grpcServer, healerSvc)

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigChan
			fmt.Println("\n[*] Shutting down Omni-Healer UDS server...")
			grpcServer.GracefulStop()
		}()

		fmt.Printf("[✓] Omni-Healer: Listening on UDS socket %s (Ed25519 Non-Repudiation Active)\n", *udsSocket)
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Fprintf(os.Stderr, "[-] gRPC serve error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 2. Standalone CLI Healer Mode
	fmt.Println("=======================================================")
	fmt.Println("  🛡️  AEGIS AUTOPILOT HEALER (SERVICE C)")
	fmt.Printf("  Dry-Run Mode: %v\n", *dryRun)
	fmt.Println("=======================================================")

	wafInj := waf.NewWafInjector()
	pu := pkgmgr.NewPackageUpgrader()
	super := supervisor.NewProcessSupervisor()

	if *nginxConf != "" {
		fmt.Printf("[+] Ingesting Nginx configuration: %s\n", *nginxConf)
		if *dryRun {
			fmt.Println("[DRY-RUN] Would inject HTTP 415 Brotli drop rule and FastCGI buffers into Nginx")
		} else {
			applied, err := wafInj.InjectNginx(*nginxConf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to patch Nginx: %v\n", err)
			} else if applied {
				fmt.Println("[✓] Successfully injected Aegis Virtual Patch into Nginx!")
			} else {
				fmt.Println("[*] Nginx already contains Aegis Virtual Patch (Idempotent)")
			}
		}
	}

	if *haproxyConf != "" {
		fmt.Printf("[+] Ingesting HAProxy configuration: %s\n", *haproxyConf)
		if *dryRun {
			fmt.Println("[DRY-RUN] Would inject HTTP 415 Brotli drop rule into HAProxy frontend")
		} else {
			applied, err := wafInj.InjectHAProxy(*haproxyConf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to patch HAProxy: %v\n", err)
			} else if applied {
				fmt.Println("[✓] Successfully injected Aegis Guard into HAProxy!")
			}
		}
	}

	if *apacheConf != "" {
		fmt.Printf("[+] Ingesting Apache configuration: %s\n", *apacheConf)
		if *dryRun {
			fmt.Println("[DRY-RUN] Would inject mod_headers / mod_security2 guard into Apache")
		} else {
			applied, err := wafInj.InjectApache(*apacheConf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to patch Apache: %v\n", err)
			} else if applied {
				fmt.Println("[✓] Successfully injected Aegis Guard into Apache!")
			}
		}
	}

	if *upgradeRuntime != "" {
		fmt.Printf("[+] Requesting package upgrade for runtime: %s (Manager: %s)\n", *upgradeRuntime, pu.Manager)
		out, err := pu.ExecuteUpgrade(*upgradeRuntime, *dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Upgrade execution error: %v\n", err)
		} else {
			fmt.Printf("[✓] Upgrade Output:\n%s\n", out)
		}
	}

	if *reloadService != "" {
		fmt.Printf("[+] Requesting service reload for: %s\n", *reloadService)
		out, err := super.ReloadService(*reloadService, *dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Reload error: %v\n", err)
		} else {
			fmt.Printf("[✓] Service Reload Output:\n%s\n", out)
		}
	}

	if _, err := os.Stat(*findingsPath); err == nil && *nginxConf == "" && *upgradeRuntime == "" {
		data, err := os.ReadFile(*findingsPath)
		if err == nil {
			var report AuditReportInput
			if err := json.Unmarshal(data, &report); err == nil {
				fmt.Printf("[+] Ingested %d findings from %s\n", len(report.BinaryFindings), *findingsPath)
				for _, f := range report.BinaryFindings {
					if f.IsVulnerable {
						fmt.Printf("  ⚠️  Vulnerable target: %s [%s] -> %s\n", f.FilePath, f.Severity, f.VulnerabilityID)
						fmt.Printf("     Remediation Threshold: %s\n", f.SafeThreshold)
					}
				}
			}
		}
	}

	fmt.Println("\n[✓] Aegis Healer execution completed.")
}
