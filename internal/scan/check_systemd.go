package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SystemdCheck finds root-run systemd services whose unit file or ExecStart
// target is writable. It reads unit files and probes write access only.
type SystemdCheck struct{}

func (SystemdCheck) Name() string { return "systemd" }

var systemdDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/lib/systemd/system",
	"/usr/lib/systemd/system",
}

func (sd *SystemdCheck) Detect(c *Context) []Finding {
	var findings []Finding
	seenUnit := map[string]bool{}
	seenBin := map[string]bool{}

	for _, dir := range systemdDirs {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() || d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
				return nil
			}
			if !strings.HasSuffix(path, ".service") {
				return nil
			}

			// A writable unit file is game over: you can set ExecStart and
			// User=root yourself.
			if writable(path) && !seenUnit[path] {
				seenUnit[path] = true
				name := strings.TrimSuffix(filepath.Base(path), ".service")
				findings = append(findings, Finding{
					Check:       sd.Name(),
					Title:       "Writable systemd unit: " + filepath.Base(path),
					Category:    "systemd",
					Confidence:  ConfHigh,
					BlastRadius: BlastReversible,
					Evidence:    "unit file is writable: " + path,
					Command:     "# back up " + path + ", set in [Service]:\n#   ExecStart=/bin/sh -c 'cp /bin/bash /tmp/.b; chmod +s /tmp/.b'\n#   User=root\n# then (if allowed): systemctl daemon-reload && systemctl restart " + name + "  ; /tmp/.b -p",
					Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-.service-files",
				})
			}

			content, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			runsAsRoot, execs := parseUnit(string(content))
			if !runsAsRoot {
				return nil
			}
			for _, bin := range execs {
				if seenBin[bin] {
					continue
				}
				if info, e := os.Stat(bin); e == nil && info.Mode().IsRegular() && writable(bin) {
					seenBin[bin] = true
					findings = append(findings, Finding{
						Check:       sd.Name(),
						Title:       "Writable binary run by root systemd unit: " + bin,
						Category:    "systemd",
						Confidence:  ConfHigh,
						BlastRadius: BlastReversible,
						Evidence:    filepath.Base(path) + " (root) ExecStart -> writable " + bin,
						Command:     "# back up " + bin + ", replace it with a root payload, then restart the unit (or wait/reboot)",
						Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-.service-files",
					})
				}
			}
			return nil
		})
	}
	return findings
}

// parseUnit reports whether a system unit runs as root (the default unless User=
// names a non-root account) and the absolute Exec* binaries it launches. Pure
// function for testability.
func parseUnit(content string) (runsAsRoot bool, execPaths []string) {
	runsAsRoot = true
	for _, line := range strings.Split(content, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		i := strings.IndexByte(l, '=')
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(l[:i])
		val := l[i+1:]
		switch key {
		case "User":
			u := strings.TrimSpace(val)
			if u != "" && u != "root" && u != "0" {
				runsAsRoot = false
			}
		case "ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop":
			if p, ok := firstExecPath(val); ok {
				execPaths = append(execPaths, p)
			}
		}
	}
	return runsAsRoot, execPaths
}

// firstExecPath strips systemd's Exec prefixes (- @ + ! !!) and returns the
// leading absolute path, if any.
func firstExecPath(val string) (string, bool) {
	val = strings.TrimSpace(val)
	val = strings.TrimLeft(val, "-@+!")
	val = strings.TrimSpace(val)
	fields := strings.Fields(val)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return "", false
	}
	return fields[0], true
}
