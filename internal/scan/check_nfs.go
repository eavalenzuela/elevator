package scan

import (
	"os"
	"strings"
)

// NFSCheck reports NFS exports configured with no_root_squash, which let a
// client with root on a machine it controls write root-owned files (e.g. a SUID
// shell) into the export. It only reads /etc/exports.
type NFSCheck struct{}

func (NFSCheck) Name() string { return "nfs" }

func (n *NFSCheck) Detect(c *Context) []Finding {
	content, err := os.ReadFile("/etc/exports")
	if err != nil {
		return nil
	}
	var findings []Finding
	for _, line := range strings.Split(string(content), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.Contains(l, "no_root_squash") {
			findings = append(findings, Finding{
				Check:       n.Name(),
				Title:       "NFS export with no_root_squash",
				Category:    "nfs",
				Confidence:  ConfMedium,
				BlastRadius: BlastReversible,
				Evidence:    "/etc/exports: " + l,
				Command:     "# from a host you have root on: mount this export, then\n#   cp /bin/bash <mount>/.b && chmod +s <mount>/.b\n# back on the target:  <export-path>/.b -p",
				Reference:   "https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting",
			})
		}
	}
	return findings
}
