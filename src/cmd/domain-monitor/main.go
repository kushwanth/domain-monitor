// Command domain-monitor starts the domain monitoring daemon.
package main

import (
	"os"

	"domain_monitor/src/internal/monitor"
)

func main() {
	os.Exit(monitor.MainExitCode())
}
