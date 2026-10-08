// Command vaultty is an encrypted SSH host manager for the terminal.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/maulai/vaultty/internal/config"
	"github.com/maulai/vaultty/internal/tui"
)

// version is set at build time with -ldflags "-X main.version=...".
var version string

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("vaultty", appVersion())
		return
	}
	cfg, firstRun, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "vaultty: load config:", err)
		os.Exit(1)
	}
	if err := tui.Run(cfg, firstRun, appVersion()); err != nil {
		fmt.Fprintln(os.Stderr, "vaultty:", err)
		os.Exit(1)
	}
}

// appVersion returns the version set at build time, else the module version
// recorded by go install, else "dev".
func appVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return strings.TrimPrefix(bi.Main.Version, "v")
	}
	return "dev"
}
