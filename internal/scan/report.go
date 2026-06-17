package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// SortFindings orders findings best-first (highest confidence, safest route).
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].score() > fs[j].score()
	})
}

// RenderJSON writes findings as a JSON array for piping/diffing.
func RenderJSON(w io.Writer, findings []Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if findings == nil {
		findings = []Finding{}
	}
	return enc.Encode(findings)
}

// RenderText writes a human-readable ranked report. The emitted Command lines
// are for the operator to run; this tool does not execute them.
func RenderText(w io.Writer, findings []Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No privilege-escalation routes detected by the current checks.")
		return
	}
	fmt.Fprintf(w, "Found %d candidate route(s), ranked:\n\n", len(findings))
	for i, f := range findings {
		fmt.Fprintf(w, "[%d] %s\n", i+1, f.Title)
		fmt.Fprintf(w, "    category=%s  confidence=%s  blast=%s\n", f.Category, f.Confidence, f.BlastRadius)
		if f.Evidence != "" {
			fmt.Fprintf(w, "    evidence : %s\n", f.Evidence)
		}
		if f.Command != "" {
			fmt.Fprintf(w, "    run      :\n")
			for _, line := range strings.Split(f.Command, "\n") {
				fmt.Fprintf(w, "      %s\n", line)
			}
		}
		if f.Reference != "" {
			fmt.Fprintf(w, "    ref      : %s\n", f.Reference)
		}
		fmt.Fprintln(w)
	}
}
