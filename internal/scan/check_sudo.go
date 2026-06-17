package scan

import (
	"strings"
)

// SudoCheck reads the current user's sudo privileges with `sudo -n -l`
// (non-interactive, listing only — it never runs a sudo command) and reports
// NOPASSWD entries that lead to root, correlating binaries against GTFOBins.
type SudoCheck struct{}

func (SudoCheck) Name() string { return "sudo" }

func (s *SudoCheck) Detect(c *Context) []Finding {
	// -n: never prompt; -l: list privileges. Read-only.
	out, err := c.run("sudo", "-n", "-l")
	if err != nil && strings.TrimSpace(out) == "" {
		// sudo absent, or a password is required and nothing is listable.
		return nil
	}
	return parseSudoListing(out)
}

// parseSudoListing turns `sudo -n -l` output into findings. Pure function so it
// can be unit-tested without invoking sudo.
func parseSudoListing(out string) []Finding {
	const checkName = "sudo"
	var findings []Finding
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !strings.Contains(line, ")") {
			continue
		}
		// We only care about privilege lines: "(runas) [TAG:] command".
		// Find the runas clause and what follows it.
		idx := strings.Index(line, ")")
		rest := strings.TrimSpace(line[idx+1:])
		if rest == "" {
			continue
		}

		nopasswd := strings.Contains(rest, "NOPASSWD:")
		rest = strings.TrimPrefix(rest, "NOPASSWD:")
		rest = strings.TrimPrefix(strings.TrimSpace(rest), "PASSWD:")
		cmdSpec := strings.TrimSpace(rest)

		// Full sudo rights -> direct root shell.
		if cmdSpec == "ALL" || cmdSpec == "ALL : ALL" {
			conf := ConfHigh
			cmd := "sudo /bin/sh"
			ev := "sudo -l: " + line
			if !nopasswd {
				conf = ConfMedium // needs your password; still a route if you have it
				cmd = "sudo -i   # (will prompt for your password)"
			}
			findings = append(findings, Finding{
				Check:       checkName,
				Title:       "Unrestricted sudo (ALL) — direct root",
				Category:    "sudo",
				Confidence:  conf,
				BlastRadius: BlastSafe,
				Evidence:    ev,
				Command:     cmd,
				Reference:   "https://gtfobins.github.io/",
			})
			continue
		}

		// Specific binaries: correlate each against GTFOBins.
		for _, tok := range strings.Fields(cmdSpec) {
			if !strings.HasPrefix(tok, "/") {
				continue // skip args, env assignments, tags
			}
			tech, ok := lookupGTFO(tok)
			if !ok || tech.Sudo == "" {
				continue
			}
			conf := ConfHigh
			note := ""
			if !nopasswd {
				conf = ConfMedium
				note = "  # (sudo will prompt for your password)"
			}
			findings = append(findings, Finding{
				Check:       checkName,
				Title:       "Sudo-runnable " + baseName(tok) + " — GTFOBins shell escape",
				Category:    "sudo",
				Confidence:  conf,
				BlastRadius: BlastSafe,
				Evidence:    "sudo -l: " + line,
				Command:     renderCmd(tech.Sudo, tok) + note,
				Reference:   tech.Ref,
			})
		}
	}
	return findings
}
