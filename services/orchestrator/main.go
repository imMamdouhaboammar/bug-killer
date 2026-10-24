package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aegis/orchestrator/crawler"
	"github.com/aegis/orchestrator/docker"
	"github.com/aegis/orchestrator/ledger"
	"github.com/aegis/orchestrator/procmap"
)

func main() {
	targetRoot := flag.String("path", ".", "Target root directory to scan")
	outputPath := flag.String("out", "coverage-ledger.json", "Output coverage ledger JSON path")
	scanBinaries := flag.Bool("scan-binaries", true, "Include system binary directories (/usr/bin, /usr/local/bin, /opt)")
	scanDocker := flag.Bool("docker", true, "Inspect Docker daemon via /var/run/docker.sock")
	scanProcs := flag.Bool("procs", true, "Inspect active host running processes")
	workers := flag.Int("workers", 16, "Concurrency worker pool size")
	flag.Parse()

	startTime := time.Now()
	hostname, _ := os.Hostname()
	covLedger := ledger.NewCoverageLedger(hostname)

	fmt.Printf("[+] Aegis Orchestrator: Starting reconnaissance on target '%s'\n", *targetRoot)

	// 1. Filesystem Crawl
	roots := []string{*targetRoot}
	if *scanBinaries {
		systemPaths := []string{"/usr/bin", "/usr/local/bin", "/opt"}
		for _, sp := range systemPaths {
			if _, err := os.Stat(sp); err == nil {
				roots = append(roots, sp)
			}
		}
	}

	fc := crawler.NewFileCrawler(crawler.CrawlerConfig{
		RootPaths:     roots,
		MaxWorkers:    *workers,
		CollectBinary: *scanBinaries,
	})

	fsAssets := fc.Crawl()
	fmt.Printf("[+] Filesystem Crawler: Discovered %d runtime/config assets\n", len(fsAssets))
	for _, a := range fsAssets {
		covLedger.AddAsset(a)
	}

	// 2. Process Map
	if *scanProcs {
		pm := procmap.NewProcessMapper()
		procAssets := pm.ScanActiveProcesses()
		fmt.Printf("[+] Process Mapper: Discovered %d active runtime processes\n", len(procAssets))
		for _, a := range procAssets {
			covLedger.AddAsset(a)
		}
	}

	// 3. Docker Container Inspection
	if *scanDocker {
		di := docker.NewDockerInspector("/var/run/docker.sock")
		dockerAssets := di.InspectRunningContainers()
		if len(dockerAssets) > 0 {
			fmt.Printf("[+] Docker Inspector: Discovered %d running containers\n", len(dockerAssets))
			for _, a := range dockerAssets {
				covLedger.AddAsset(a)
			}
		} else {
			fmt.Printf("[*] Docker Inspector: 0 running containers or socket inactive\n")
		}
	}

	covLedger.ScanDuration = time.Since(startTime).String()

	if err := covLedger.WriteToFile(*outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to write coverage ledger: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[✓] Coverage Ledger successfully generated: %s (Total Assets: %d, Elapsed: %s)\n",
		*outputPath, covLedger.TotalAssets, covLedger.ScanDuration)
}
