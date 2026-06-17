package scan

import (
	"os"
	"strconv"
	"strings"
)

// KernelCheck emits INFORMATION-ONLY suggestions for kernel/userspace local
// exploits keyed on the running kernel version. These never carry a runnable
// command: version-keyed matching is false-positive-prone (distro backports)
// and the exploits are destructive (a failed kernel LPE can panic the host), so
// the operator verifies the patch level and runs anything manually.
type KernelCheck struct{}

func (KernelCheck) Name() string { return "kernel" }

type kernelVuln struct {
	name    string
	cve     string
	minIncl int // version key, inclusive lower bound (0 = no lower bound)
	maxIncl int // version key, inclusive upper bound
	ref     string
}

// vkey packs major.minor.patch into a comparable integer.
func vkey(maj, min, patch int) int { return maj*1_000_000 + min*1000 + patch }

var kernelVulns = []kernelVuln{
	{"DirtyCOW", "CVE-2016-5195", 0, vkey(4, 8, 2), "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"},
	{"DirtyPipe", "CVE-2022-0847", vkey(5, 8, 0), vkey(5, 16, 10), "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"},
	{"OverlayFS local root (Ubuntu)", "CVE-2021-3493", 0, vkey(5, 11, 999), "https://nvd.nist.gov/vuln/detail/CVE-2021-3493"},
	{"OverlayFS local root", "CVE-2023-0386", vkey(5, 0, 0), vkey(6, 2, 0), "https://nvd.nist.gov/vuln/detail/CVE-2023-0386"},
}

func (k *KernelCheck) Detect(c *Context) []Finding {
	var findings []Finding

	rel := readKernelRelease()
	if maj, min, patch, ok := parseKernelVersion(rel); ok {
		key := vkey(maj, min, patch)
		for _, v := range kernelVulns {
			if (v.minIncl == 0 || key >= v.minIncl) && key <= v.maxIncl {
				findings = append(findings, Finding{
					Check:       k.Name(),
					Title:       v.name + " (" + v.cve + ") — kernel " + rel + " may be in range",
					Category:    "kernel-lpe",
					Confidence:  ConfLow, // version-keyed; verify patch level (backports!)
					BlastRadius: BlastDestructive,
					Evidence:    "running kernel " + rel + " falls in the affected range; CONFIRM the distro patch level before trying anything",
					Reference:   v.ref,
				})
			}
		}
	}

	// PwnKit is a userspace (polkit) LPE, not kernel-version keyed: flag on the
	// mere presence of pkexec, info-only.
	if _, err := os.Stat("/usr/bin/pkexec"); err == nil {
		findings = append(findings, Finding{
			Check:       k.Name(),
			Title:       "pkexec present — PwnKit (CVE-2021-4034) if polkit is unpatched",
			Category:    "kernel-lpe",
			Confidence:  ConfLow,
			BlastRadius: BlastSafe,
			Evidence:    "/usr/bin/pkexec exists; confirm the polkit version is patched",
			Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2021-4034",
		})
	}
	return findings
}

func readKernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// parseKernelVersion parses the leading major.minor.patch of a kernel release
// string like "5.4.0-91-generic". Pure function for testability.
func parseKernelVersion(rel string) (maj, min, patch int, ok bool) {
	if rel == "" {
		return 0, 0, 0, false
	}
	// Take the part before the first '-' and split on '.'.
	core := rel
	if i := strings.IndexByte(core, '-'); i >= 0 {
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) < 2 {
		return 0, 0, 0, false
	}
	var err error
	if maj, err = strconv.Atoi(parts[0]); err != nil {
		return 0, 0, 0, false
	}
	if min, err = strconv.Atoi(parts[1]); err != nil {
		return 0, 0, 0, false
	}
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2]) // patch is optional/best-effort
	}
	return maj, min, patch, true
}
