# elevator

A read-only Linux **privilege-escalation triage** tool.

Run it on a host you are authorized to test. It enumerates local privesc routes —
sudo misconfigurations, SUID/SGID binaries, Linux capabilities, writable sensitive
files — correlates each to a known technique, and prints a **ranked report with the
exact command you would run**, a confidence rating, a blast-radius rating, and a
citation.

**It is emit-only. elevator finds and explains routes; it does not exploit them.**
You run the emitted commands yourself. This is deliberate:

- it mirrors how LinPEAS / linux-exploit-suggester / GTFOBins already work;
- it keeps a human at the trigger, so an unreliable route never fires unattended
  (the same reason you don't auto-run kernel exploits on a client's box);
- it keeps the tool squarely on the right side of "authorized assessment."

> For authorized security testing, CTF, and education only.

## Why a Go static binary

- **No runtime dependency.** A single static binary — no Python or other interpreter
  needed on the target. Drop it on a minimal or locked-down box and it just runs.
- **Effortless cross-compilation.** Build for amd64 / arm64 / 386 / … from one machine.
- **Offline.** No network, no phone-home.

## Build

```sh
go build -o elevator .

# static, stripped — recommended for dropping on other hosts:
CGO_ENABLED=0 go build -ldflags="-s -w" -o elevator .

# cross-compile, e.g. for arm64:
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o elevator-arm64 .
```

## Usage

```sh
./elevator                    # scan, ranked human-readable report
./elevator -json              # machine-readable, for piping / diffing
./elevator -roots /usr,/opt   # limit the filesystem walk (faster than scanning /)
./elevator -timeout 60s       # overall scan budget (default 2m)
./elevator -quiet             # suppress the banner
```

Each finding prints the evidence (what was detected), the exact command for **you**
to run, a confidence and blast-radius rating, and a reference. You decide and run it.

## Checks (current)

- **sudo** — parses `sudo -n -l` (a read-only listing; it never runs a sudo command)
  for NOPASSWD entries and unrestricted sudo, correlating binaries to GTFOBins.
- **filesystem** — a single walk that finds SUID/SGID-root binaries (GTFOBins-correlated)
  and Linux file capabilities that grant escalation (`cap_setuid`, `cap_dac_*`, …),
  reading the `security.capability` xattr directly (no `getcap` dependency).
- **writable** — write access to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`,
  and `/etc/sudoers.d/`.

Routes the architecture already supports as drop-ins (roadmap): writable/PATH-hijack
cron jobs, writable systemd units, `docker`/`lxd` group membership, NFS `no_root_squash`,
and information-only kernel-LPE suggestions.

## Blast radius

Findings are tagged:

- `safe` — deterministic, no host modification;
- `reversible` — bounded host change (back up the file first);
- `destructive` — may crash or corrupt the host (e.g. kernel exploits).

The report ranks reliable, safe routes first.

## Adding a route

Implement the `scan.Check` interface (`Name()` and `Detect(*Context) []Finding`) and
add it to `DefaultChecks()` in `internal/scan/check.go`. Each `Finding` carries the
operator command, confidence, blast-radius, and a citation; the report and JSON layers
are generic, so a new check needs no rendering code.

## Status

This is a rewrite of the original Python proof-of-concept (a gzip+hex payload packer)
into a Go triage tool. The legacy `elevator.py` / `exploit_encoder.py` remain for
reference and are superseded by this binary.
