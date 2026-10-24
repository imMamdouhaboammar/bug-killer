package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/aegis/healer/pkgmgr"
	"github.com/aegis/healer/supervisor"
	"github.com/aegis/healer/waf"
)

type AuditFinding struct {
	FilePath            string `json:"file_path"`
	IsVulnerable        bool   `json:"is_vulnerable"`
	VulnerabilityID     string `json:"vulnerability_id"`
	Severity            string `json:"severity"`
	SafeThreshold       string `json:"safe_threshold"`
	ReachabilityStatus  string `json:"reachability_status"`
}

type AuditReportInput struct {
	HostID         string         `json:"host_id"`
	BinaryFindings []AuditFinding `json:"binary_findings"`
}

func main() {
	findingsPath := flag.String("findings", "findings.json", "Path to findings.json from inspector")
	nginxConf := flag.String("nginx", "", "Path to Nginx config to inject virtual patch")
	haproxyConf := flag.String("haproxy", "", "Path to HAProxy config to inject guard")
	apacheConf := flag.String("apache", "", "Path to Apache config to inject guard")
	upgradeRuntime := flag.String("upgrade", "", "Upgrade runtime via package manager ('php' or 'node')")
	reloadService := flag.String("reload", "", "Reload system service after patch ('nginx', 'php-fpm', etc.)")
	dryRun := flag.Bool("dry-run", false, "Preview actions without applying changes")
	flag.Parse()

	fmt.Println("=======================================================")
	fmt.Println("  🛡️  AEGIS AUTOPILOT HEALER (SERVICE C)")
	fmt.Printf("  Dry-Run Mode: %v\n", *dryRun)
	fmt.Println("=======================================================")

	wafInj := waf.NewWafInjector()
	pu := pkgmgr.NewPackageUpgrader()
	super := supervisor.NewProcessSupervisor()

	// 1. WAF Virtual Patch Injection
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

	// 2. Package Manager Upgrade
	if *upgradeRuntime != "" {
		fmt.Printf("[+] Requesting package upgrade for runtime: %s (Manager: %s)\n", *upgradeRuntime, pu.Manager)
		out, err := pu.ExecuteUpgrade(*upgradeRuntime, *dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Upgrade execution error: %v\n", err)
		} else {
			fmt.Printf("[✓] Upgrade Output:\n%s\n", out)
		}
	}

	// 3. Service Reload
	if *reloadService != "" {
		fmt.Printf("[+] Requesting service reload for: %s\n", *reloadService)
		out, err := super.ReloadService(*reloadService, *dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Reload error: %v\n", err)
		} else {
			fmt.Printf("[✓] Service Reload Output:\n%s\n", out)
		}
	}

	// 4. Auto-audit findings report if file exists
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
