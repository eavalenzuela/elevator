package scan

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"time"
)

// Check is one read-only privesc enumerator. Detect inspects the host and
// returns candidate routes. Implementations must not mutate state or escalate.
type Check interface {
	Name() string
	Detect(c *Context) []Finding
}

// Context carries shared scan configuration and read-only helpers.
type Context struct {
	Ctx         context.Context
	SearchRoots []string // filesystem roots for fs walks (default ["/"])
	CmdTimeout  time.Duration
	UID         int
	GIDs        []int
}

// NewContext resolves the current identity and applies defaults.
func NewContext(ctx context.Context, roots []string) *Context {
	if len(roots) == 0 {
		roots = []string{"/"}
	}
	gids, _ := os.Getgroups()
	return &Context{
		Ctx:         ctx,
		SearchRoots: roots,
		CmdTimeout:  10 * time.Second,
		UID:         os.Getuid(),
		GIDs:        gids,
	}
}

// run executes a non-mutating informational command with a timeout and returns
// its combined output. Only ever used for read-only queries (e.g. `sudo -n -l`).
func (c *Context) run(name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(c.Ctx, c.CmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// DefaultChecks is the MVP set of routes the tool knows how to find and explain.
// Adding a route is adding one Check here; the report/JSON layers are generic.
func DefaultChecks() []Check {
	return []Check{
		&SudoCheck{},
		&FilesystemCheck{}, // SUID/SGID + capabilities (single filesystem walk)
		&WritableCheck{},
		&CronCheck{},
		&GroupsCheck{},
		&NFSCheck{},
		&KernelCheck{}, // information-only suggestions
	}
}

// Run executes every check and returns the combined findings.
func Run(c *Context, checks []Check) []Finding {
	var all []Finding
	for _, ch := range checks {
		if c.Ctx.Err() != nil {
			break
		}
		all = append(all, ch.Detect(c)...)
	}
	return all
}
