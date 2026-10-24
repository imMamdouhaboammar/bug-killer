package main

import (
	"fmt"
	"os"

	"github.com/aegis/orchestrator/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Omni-Agent error: %v\n", err)
		os.Exit(1)
	}
}
