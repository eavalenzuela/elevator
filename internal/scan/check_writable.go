package scan

import (
	"os"
	"path/filepath"
)

// WritableCheck probes a fixed set of sensitive files for write access (via
// access(2)) and reports the corresponding escalation route for each. It only
// tests permissions; it never writes anything.
type WritableCheck struct{}

func (WritableCheck) Name() string { return "writable" }

func (w *WritableCheck) Detect(c *Context) []Finding {
	var findings []Finding

	if writable("/etc/passwd") {
		findings = append(findings, Finding{
			Check:       w.Name(),
			Title:       "/etc/passwd is writable — add a uid-0 user",
			Category:    "writable-file",
			Confidence:  ConfHigh,
			BlastRadius: BlastReversible,
			Evidence:    "access(W_OK) succeeds on /etc/passwd",
			Command:     "openssl passwd -1 -salt x pass   # then append:\n# r00t:<hash>:0:0:root:/root:/bin/bash  >> /etc/passwd  (back it up first), then: su r00t",
			Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-etc-passwd",
		})
	}
	if writable("/etc/shadow") {
		findings = append(findings, Finding{
			Check:       w.Name(),
			Title:       "/etc/shadow is writable — replace root's hash",
			Category:    "writable-file",
			Confidence:  ConfHigh,
			BlastRadius: BlastReversible,
			Evidence:    "access(W_OK) succeeds on /etc/shadow",
			Command:     "# back up /etc/shadow, replace root's 2nd field with a known hash (openssl passwd -6), then: su root",
			Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
		})
	} else if readable("/etc/shadow") {
		findings = append(findings, Finding{
			Check:       w.Name(),
			Title:       "/etc/shadow is readable — offline hash cracking",
			Category:    "writable-file",
			Confidence:  ConfMedium,
			BlastRadius: BlastSafe,
			Evidence:    "access(R_OK) succeeds on /etc/shadow",
			Command:     "# copy /etc/shadow off-host and crack root's hash (john/hashcat) — not a direct root, but a path",
			Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
		})
	}

	// sudoers and any drop-in under sudoers.d
	sudoers := []string{"/etc/sudoers"}
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				sudoers = append(sudoers, filepath.Join("/etc/sudoers.d", e.Name()))
			}
		}
	}
	if writable("/etc/sudoers.d") {
		findings = append(findings, Finding{
			Check:       w.Name(),
			Title:       "/etc/sudoers.d is writable — drop in a NOPASSWD rule",
			Category:    "writable-file",
			Confidence:  ConfHigh,
			BlastRadius: BlastReversible,
			Evidence:    "access(W_OK) succeeds on directory /etc/sudoers.d",
			Command:     "echo \"$(id -un) ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/zz   # then: sudo -i",
			Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
		})
	}
	for _, sf := range sudoers {
		if writable(sf) {
			findings = append(findings, Finding{
				Check:       w.Name(),
				Title:       sf + " is writable — grant yourself NOPASSWD sudo",
				Category:    "writable-file",
				Confidence:  ConfHigh,
				BlastRadius: BlastReversible,
				Evidence:    "access(W_OK) succeeds on " + sf,
				Command:     "# back up " + sf + ", append: $(id -un) ALL=(ALL) NOPASSWD:ALL , then: sudo -i",
				Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
			})
		}
	}
	return findings
}
