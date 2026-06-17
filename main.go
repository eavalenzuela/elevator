// Command elevator is a read-only Linux privilege-escalation triage tool.
//
// It enumerates the host for local privesc routes (sudo misconfigurations,
// SUID/SGID binaries, Linux capabilities, writable sensitive files), correlates
// each to a known technique, and prints a ranked report with the EXACT command
// an operator would run — plus a confidence and blast-radius rating and a
// citation. It is emit-only: it finds and explains routes, it does not exploit
// them. You run the emitted commands yourself.
//
// For authorized security testing, CTF, and education only.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"elevator/internal/scan"
)

func main() {
	var (
		jsonOut  bool
		rootsCSV string
		timeout  time.Duration
		quiet    bool
	)
	flag.BoolVar(&jsonOut, "json", false, "emit findings as JSON")
	flag.StringVar(&rootsCSV, "roots", "/", "comma-separated filesystem roots to scan (SUID/caps)")
	flag.DurationVar(&timeout, "timeout", 2*time.Minute, "overall scan timeout")
	flag.BoolVar(&quiet, "quiet", false, "suppress the banner")
	flag.Parse()

	if !quiet && !jsonOut {
		fmt.Fprintln(os.Stderr, "elevator — read-only privesc triage. Emits commands for YOU to run; it does not exploit. Authorized use only.")
		fmt.Fprintln(os.Stderr, "")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Allow Ctrl-C to stop a long filesystem walk cleanly.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var roots []string
	for _, r := range strings.Split(rootsCSV, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roots = append(roots, r)
		}
	}

	sc := scan.NewContext(ctx, roots)
	findings := scan.Run(sc, scan.DefaultChecks())
	scan.SortFindings(findings)

	if jsonOut {
		if err := scan.RenderJSON(os.Stdout, findings); err != nil {
			fmt.Fprintln(os.Stderr, "render error:", err)
			os.Exit(1)
		}
		return
	}
	scan.RenderText(os.Stdout, findings)
}
