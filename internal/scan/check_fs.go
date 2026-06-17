package scan

import (
	"encoding/binary"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
)

// FilesystemCheck performs a single read-only walk of the search roots and
// reports two route families that both come from file attributes:
//   - SUID/SGID-root binaries (correlated against GTFOBins)
//   - Linux file capabilities that grant escalation (cap_setuid, cap_dac_*, ...)
type FilesystemCheck struct{}

func (FilesystemCheck) Name() string { return "filesystem" }

// prunedDirs are pseudo-filesystems we never descend into.
var prunedDirs = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true, "/run": true,
}

// defaultSUID are SUID-root binaries shipped by distros. They are down-ranked
// (reported as informational) unless they also match a GTFOBins escape.
var defaultSUID = map[string]bool{
	"su": true, "sudo": true, "mount": true, "umount": true, "passwd": true,
	"chsh": true, "chfn": true, "gpasswd": true, "newgrp": true, "pkexec": true,
	"ping": true, "ping6": true, "fusermount": true, "fusermount3": true,
	"ntfs-3g": true, "ssh-keysign": true, "dbus-daemon-launch-helper": true,
	"polkit-agent-helper-1": true, "pppd": true, "at": true, "chage": true,
	"expiry": true, "crontab": true, "wall": true, "write": true,
}

// CAP bit numbers worth flagging, mapped to their names.
var capNames = map[int]string{
	0:  "cap_chown",
	1:  "cap_dac_override",
	2:  "cap_dac_read_search",
	3:  "cap_fowner",
	6:  "cap_setgid",
	7:  "cap_setuid",
	8:  "cap_setpcap",
	16: "cap_sys_module",
	18: "cap_sys_chroot",
	19: "cap_sys_ptrace",
	21: "cap_sys_admin",
	31: "cap_setfcap",
}

func (f *FilesystemCheck) Detect(c *Context) []Finding {
	var findings []Finding
	seen := map[string]bool{}

	walk := func(path string, d fs.DirEntry, err error) error {
		if c.Ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if prunedDirs[path] {
				return filepath.SkipDir
			}
			return nil
		}
		// Regular files only; never follow symlinks.
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		if seen[path] {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}

		// --- SUID / SGID root binaries ---
		mode := info.Mode()
		if mode&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid == 0 {
				seen[path] = true
				findings = append(findings, suidFinding(path, mode))
			}
		}

		// --- File capabilities ---
		if perm, eff, ok := readCaps(path); ok {
			if cf, has := capFinding(path, perm, eff); has {
				findings = append(findings, cf)
			}
		}
		return nil
	}

	for _, root := range c.SearchRoots {
		_ = filepath.WalkDir(root, walk)
	}
	return findings
}

func suidFinding(path string, mode fs.FileMode) Finding {
	bit := "SUID"
	if mode&fs.ModeSetuid == 0 {
		bit = "SGID"
	}
	base := baseName(path)
	if tech, ok := lookupGTFO(path); ok && tech.Suid != "" {
		return Finding{
			Check:       "filesystem",
			Title:       bit + "-root " + base + " — GTFOBins shell escape",
			Category:    "suid",
			Confidence:  ConfHigh,
			BlastRadius: BlastSafe,
			Evidence:    "root-owned " + bit + " binary: " + path,
			Command:     renderCmd(tech.Suid, path),
			Reference:   tech.Ref,
		}
	}
	if defaultSUID[strings.ToLower(base)] {
		return Finding{
			Check:       "filesystem",
			Title:       "Default " + bit + "-root binary " + base,
			Category:    "suid",
			Confidence:  ConfLow,
			BlastRadius: BlastSafe,
			Evidence:    "standard distro " + bit + " binary: " + path,
			Reference:   "https://gtfobins.github.io/",
		}
	}
	return Finding{
		Check:       "filesystem",
		Title:       "Non-standard " + bit + "-root binary " + base + " — investigate",
		Category:    "suid",
		Confidence:  ConfMedium,
		BlastRadius: BlastSafe,
		Evidence:    "unusual root-owned " + bit + " binary: " + path,
		Command:     "# no bundled GTFOBins entry — check its behavior; it may call helpers by relative path (PATH hijack)",
		Reference:   "https://gtfobins.github.io/",
	}
}

func capFinding(path string, perm uint64, eff bool) (Finding, bool) {
	var names []string
	for bit, name := range capNames {
		if perm&(1<<uint(bit)) != 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return Finding{}, false
	}
	base := strings.ToLower(baseName(path))
	cmd := ""
	conf := ConfMedium
	switch {
	case perm&(1<<7) != 0: // cap_setuid
		conf = ConfHigh
		switch base {
		case "python", "python3":
			cmd = path + " -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"
		case "perl":
			cmd = path + " -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"
		case "ruby":
			cmd = path + " -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'"
		case "node":
			cmd = path + " -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'"
		default:
			cmd = "# " + base + " carries cap_setuid: invoke it to drop privileges to uid 0, then exec a shell"
		}
	case perm&(1<<1) != 0: // cap_dac_override (write any file)
		cmd = "# cap_dac_override: append a uid-0 line to /etc/passwd or a NOPASSWD entry to /etc/sudoers via " + base
	case perm&(1<<2) != 0: // cap_dac_read_search (read any file)
		cmd = "# cap_dac_read_search: read /etc/shadow with " + base + " and crack root's hash offline"
	default:
		cmd = "# capability-based escalation — see GTFOBins capabilities"
	}
	effStr := ""
	if eff {
		effStr = " (effective)"
	}
	return Finding{
		Check:       "filesystem",
		Title:       "Capability " + strings.Join(names, ",") + " on " + baseName(path),
		Category:    "capabilities",
		Confidence:  conf,
		BlastRadius: BlastSafe,
		Evidence:    path + " has " + strings.Join(names, ",") + effStr,
		Command:     cmd,
		Reference:   "https://gtfobins.github.io/#+capabilities",
	}, true
}

// readCaps reads the security.capability xattr (no external tools) and decodes
// it. Returns ok=false when the file has no capability xattr.
func readCaps(path string) (permitted uint64, effective bool, ok bool) {
	buf := make([]byte, 64)
	n, err := syscall.Getxattr(path, "security.capability", buf)
	if err != nil || n < 12 {
		return 0, false, false
	}
	return decodeCaps(buf[:n])
}

// decodeCaps parses a struct vfs_cap_data (little-endian). Pure function so the
// xattr decoding can be unit-tested without a setcap'd binary on disk.
func decodeCaps(b []byte) (permitted uint64, effective bool, ok bool) {
	if len(b) < 12 {
		return 0, false, false
	}
	magic := binary.LittleEndian.Uint32(b[0:4])
	rev := magic & 0xff000000
	effective = magic&0x1 != 0
	permitted = uint64(binary.LittleEndian.Uint32(b[4:8]))
	if (rev == 0x02000000 || rev == 0x03000000) && len(b) >= 16 {
		permitted |= uint64(binary.LittleEndian.Uint32(b[12:16])) << 32
	}
	return permitted, effective, true
}
