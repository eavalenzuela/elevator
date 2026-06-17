package scan

import (
	"encoding/binary"
	"io/fs"
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
