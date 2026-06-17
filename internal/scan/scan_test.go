package scan

import (
	"encoding/binary"
	"io/fs"
	"os"
	"strings"
	"testing"
)

func TestParseSudoListing(t *testing.T) {
	out := `Matching Defaults entries for user on host:
    env_reset, mail_badpass

User user may run the following commands on host:
    (root) NOPASSWD: /usr/bin/find
    (ALL : ALL) ALL`

	got := parseSudoListing(out)
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(got), got)
	}

	var sawFind, sawAll bool
	for _, f := range got {
		if strings.Contains(f.Title, "find") {
			sawFind = true
			if f.Confidence != ConfHigh {
				t.Errorf("NOPASSWD find should be high confidence, got %s", f.Confidence)
			}
			if !strings.Contains(f.Command, "/bin/sh") {
				t.Errorf("find command missing shell escape: %q", f.Command)
			}
		}
		if strings.Contains(f.Title, "Unrestricted sudo") {
			sawAll = true
		}
	}
	if !sawFind || !sawAll {
		t.Errorf("missing expected findings: find=%v all=%v", sawFind, sawAll)
	}
}

func TestDecodeCapsSetuid(t *testing.T) {
	// Craft a VFS_CAP_REVISION_2 xattr with the effective flag and cap_setuid.
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b[0:4], 0x02000000|0x1) // rev2 + effective
	binary.LittleEndian.PutUint32(b[4:8], 1<<7)           // permitted[0]: cap_setuid (bit 7)

	perm, eff, ok := decodeCaps(b)
	if !ok {
		t.Fatal("decodeCaps returned ok=false")
	}
	if !eff {
		t.Error("expected effective=true")
	}
	if perm&(1<<7) == 0 {
		t.Errorf("expected cap_setuid bit set, perm=%#x", perm)
	}
}

func TestDecodeCapsTooShort(t *testing.T) {
	if _, _, ok := decodeCaps([]byte{0x01, 0x02}); ok {
		t.Error("expected ok=false for truncated buffer")
	}
}

func TestLookupGTFO(t *testing.T) {
	if _, ok := lookupGTFO("/usr/local/bin/Find"); !ok {
		t.Error("lookupGTFO should be case-insensitive and match by basename")
	}
	if _, ok := lookupGTFO("/usr/bin/totally-not-a-gtfobin"); ok {
		t.Error("lookupGTFO should not match unknown binary")
	}
}

func TestCapFindingSetuidInterpreter(t *testing.T) {
	f, ok := capFinding("/usr/bin/python3", 1<<7, true)
	if !ok {
		t.Fatal("capFinding returned ok=false for cap_setuid")
	}
	if f.Confidence != ConfHigh {
		t.Errorf("cap_setuid should be high confidence, got %s", f.Confidence)
	}
	if !strings.Contains(f.Command, "setuid(0)") {
		t.Errorf("python cap_setuid command should call setuid(0): %q", f.Command)
	}
}

func TestSuidFindingCorrelatesGTFO(t *testing.T) {
	f := suidFinding("/usr/bin/find", fs.ModeSetuid)
	if f.Confidence != ConfHigh {
		t.Errorf("SUID find should be high confidence, got %s", f.Confidence)
	}
	if !strings.Contains(f.Command, "-exec /bin/sh -p") {
		t.Errorf("SUID find should emit the -p preserving escape: %q", f.Command)
	}
}

func TestExtractAbsPaths(t *testing.T) {
	got := extractAbsPaths("*/5 * * * * root /opt/app/run.sh --flag /tmp/x")
	want := map[string]bool{"/opt/app/run.sh": true, "/tmp/x": true}
	if len(got) != 2 {
		t.Fatalf("want 2 paths, got %v", got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected path %q", p)
		}
	}
	if extractAbsPaths("# /etc/commented/out") != nil {
		t.Error("comment lines should yield no paths")
	}
	if extractAbsPaths("PATH=/usr/bin:/bin") != nil {
		t.Error("var assignments should yield no paths")
	}
}

func TestParseKernelVersion(t *testing.T) {
	maj, min, patch, ok := parseKernelVersion("5.16.10-generic")
	if !ok || maj != 5 || min != 16 || patch != 10 {
		t.Fatalf("got %d.%d.%d ok=%v", maj, min, patch, ok)
	}
	if _, _, _, ok := parseKernelVersion(""); ok {
		t.Error("empty release should not parse")
	}
}

func TestKernelVulnRange(t *testing.T) {
	// DirtyPipe range is 5.8.0 .. 5.16.10 inclusive.
	in := vkey(5, 16, 10)
	var dirtyPipe kernelVuln
	for _, v := range kernelVulns {
		if v.cve == "CVE-2022-0847" {
			dirtyPipe = v
		}
	}
	if !(in >= dirtyPipe.minIncl && in <= dirtyPipe.maxIncl) {
		t.Error("5.16.10 should be in DirtyPipe range")
	}
	if patched := vkey(5, 16, 11); patched <= dirtyPipe.maxIncl {
		t.Error("5.16.11 should be out of DirtyPipe range")
	}
}

func TestMemberGroups(t *testing.T) {
	groupFile := "root:x:0:\ndocker:x:998:alice,bob\nshadow:x:42:\nadm:x:4:bob\n"
	// alice is a named member of docker; bob is in gid 42 (shadow) via gids.
	got := memberGroups(groupFile, map[int]bool{42: true}, "alice")
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	if !set["docker"] {
		t.Error("alice should be detected in docker (named member)")
	}
	if !set["shadow"] {
		t.Error("should be detected in shadow (gid match)")
	}
	if set["adm"] {
		t.Error("alice should not be in adm")
	}
}

func TestParseUnit(t *testing.T) {
	rootUnit := "[Service]\nExecStartPre=-/usr/bin/setup\nExecStart=/opt/app/run --flag\nUser=root\n"
	root, execs := parseUnit(rootUnit)
	if !root {
		t.Error("User=root unit should run as root")
	}
	if len(execs) != 2 || execs[1] != "/opt/app/run" {
		t.Errorf("expected exec paths [/usr/bin/setup /opt/app/run], got %v", execs)
	}

	nonRoot, _ := parseUnit("[Service]\nUser=www-data\nExecStart=/opt/app/run\n")
	if nonRoot {
		t.Error("User=www-data unit should NOT run as root")
	}

	dflt, _ := parseUnit("[Service]\nExecStart=/opt/app/run\n")
	if !dflt {
		t.Error("unit without User= should default to root")
	}
}

func TestParseCronEntry(t *testing.T) {
	user, cmd, ok := parseCronEntry("*/5 * * * * root /opt/app/run.sh arg")
	if !ok || user != "root" || cmd != "/opt/app/run.sh arg" {
		t.Errorf("numeric entry: got user=%q cmd=%q ok=%v", user, cmd, ok)
	}
	user, cmd, ok = parseCronEntry("@reboot bob /home/bob/x")
	if !ok || user != "bob" || cmd != "/home/bob/x" {
		t.Errorf("@reboot entry: got user=%q cmd=%q ok=%v", user, cmd, ok)
	}
	if _, _, ok := parseCronEntry("PATH=/usr/bin:/bin"); ok {
		t.Error("PATH= assignment should not parse as an entry")
	}
	if _, _, ok := parseCronEntry("# comment"); ok {
		t.Error("comment should not parse as an entry")
	}
}

func TestWildcardAbusable(t *testing.T) {
	if b, ok := wildcardAbusable("/bin/tar -czf /backup/a.tgz *"); !ok || b != "tar" {
		t.Errorf("expected tar wildcard, got %q ok=%v", b, ok)
	}
	if _, ok := wildcardAbusable("/bin/tar -czf a.tgz /data"); ok {
		t.Error("no wildcard -> no finding")
	}
	if _, ok := wildcardAbusable("/usr/bin/find /tmp -name *.log"); ok {
		t.Error("find is not in the abusable set")
	}
}

func TestHasEnvKeepPreload(t *testing.T) {
	if !hasEnvKeepPreload(`    Defaults env_keep+="LD_PRELOAD LD_LIBRARY_PATH"`) {
		t.Error("should detect LD_PRELOAD in env_keep")
	}
	if hasEnvKeepPreload(`    Defaults env_keep+="EDITOR"`) {
		t.Error("EDITOR env_keep is not a preload route")
	}
}

func TestReadStringsAndHijack(t *testing.T) {
	// A fake "binary" that references `service` by relative name and has no
	// absolute path to it -> should be flagged as a PATH-hijack candidate.
	dir := t.TempDir()
	p := dir + "/wrapper"
	content := []byte("\x00\x00random\x00service apache2 restart\x00\x01\x02done\x00")
	if err := os.WriteFile(p, content, 0o755); err != nil {
		t.Fatal(err)
	}
	strs, err := readStrings(p, 3, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(strs) == 0 {
		t.Fatal("expected to extract some strings")
	}
	if cmd, ok := analyzeSuidPathHijack(p); !ok || cmd != "service" {
		t.Errorf("expected PATH-hijack candidate 'service', got %q ok=%v", cmd, ok)
	}
}

func TestRankingHighSafeFirst(t *testing.T) {
	in := []Finding{
		{Title: "low", Confidence: ConfLow, BlastRadius: BlastSafe},
		{Title: "high-destructive", Confidence: ConfHigh, BlastRadius: BlastDestructive},
		{Title: "high-safe", Confidence: ConfHigh, BlastRadius: BlastSafe},
	}
	SortFindings(in)
	if in[0].Title != "high-safe" {
		t.Errorf("want high-safe first, got %q", in[0].Title)
	}
	if in[2].Title != "low" {
		t.Errorf("want low last, got %q", in[2].Title)
	}
}
