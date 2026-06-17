package scan

import (
	"path/filepath"
	"syscall"
)

// POSIX access(2) modes (not exported by the syscall package).
const (
	rOK = 0x4
	wOK = 0x2
	xOK = 0x1
)

func baseName(p string) string { return filepath.Base(p) }

// writable reports whether the current process can write to path, honoring the
// effective credentials (and ACLs) via access(2). Read-only probe.
func writable(path string) bool {
	return syscall.Access(path, wOK) == nil
}

// readable reports whether the current process can read path.
func readable(path string) bool {
	return syscall.Access(path, rOK) == nil
}
