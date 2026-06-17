// Package scan implements the read-only privilege-escalation triage engine.
//
// Design contract: every check in this package is READ-ONLY. A check may read
// files, stat the filesystem, read extended attributes, and run non-mutating
// informational commands (e.g. `sudo -n -l`). A check MUST NOT modify the
// system or execute any escalation. The tool is emit-only: it reports candidate
// routes and the exact command an operator would run, and the operator runs it
// themselves. Nothing here pulls the trigger.
package scan

// Confidence is how sure the check is that the route is exploitable as reported.
type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// BlastRadius describes what running the emitted command would do to the host.
// It is advisory metadata for the operator; the tool never runs the command.
type BlastRadius string

const (
	// BlastSafe: deterministic, no host modification, no cleanup needed.
	BlastSafe BlastRadius = "safe"
	// BlastReversible: modifies host state but in a bounded, restorable way.
	BlastReversible BlastRadius = "reversible"
	// BlastDestructive: may crash/corrupt the host (e.g. kernel exploits).
	BlastDestructive BlastRadius = "destructive"
)

// Finding is a single candidate privilege-escalation route.
//
// Command is the exact command the OPERATOR would run to take the route. The
// tool prints it; it does not execute it.
type Finding struct {
	Check       string      `json:"check"`
	Title       string      `json:"title"`
	Category    string      `json:"category"`
	Confidence  Confidence  `json:"confidence"`
	BlastRadius BlastRadius `json:"blast_radius"`
	Evidence    string      `json:"evidence"`
	Command     string      `json:"command,omitempty"`
	Reference   string      `json:"reference,omitempty"`
}

// score ranks findings: higher confidence first, then safer (more reliable)
// routes ahead of riskier ones, since "get root" should mean "reliably".
func (f Finding) score() int {
	conf := map[Confidence]int{ConfHigh: 3, ConfMedium: 2, ConfLow: 1}[f.Confidence]
	blast := map[BlastRadius]int{BlastSafe: 3, BlastReversible: 2, BlastDestructive: 1}[f.BlastRadius]
	return conf*10 + blast
}
