package scan

import (
	"os"
	"os/user"
	"strconv"
	"strings"
)

// GroupsCheck reports membership in groups that grant a known path to root
// (docker, lxd/lxc, disk, shadow, adm). It reads /etc/group and the process
// group set; it changes nothing.
type GroupsCheck struct{}

func (GroupsCheck) Name() string { return "groups" }

type groupRoute struct {
	title      string
	command    string
	confidence Confidence
	blast      BlastRadius
	ref        string
}

var groupRoutes = map[string]groupRoute{
	"docker": {
		title:      "Member of 'docker' group — mount host filesystem as root",
		command:    "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
		confidence: ConfHigh,
		blast:      BlastSafe,
		ref:        "https://gtfobins.github.io/gtfobins/docker/",
	},
	"lxd": {
		title:      "Member of 'lxd' group — privileged container with host / mounted",
		command:    "# lxc image import ./alpine.tar.gz --alias a; lxc init a r -c security.privileged=true\n# lxc config device add r host disk source=/ path=/mnt/root recursive=true; lxc start r; lxc exec r /bin/sh",
		confidence: ConfHigh,
		blast:      BlastReversible,
		ref:        "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation",
	},
	"lxc": {
		title:      "Member of 'lxc' group — privileged container with host / mounted",
		command:    "# same as lxd: init a privileged container and add the host root as a disk device",
		confidence: ConfHigh,
		blast:      BlastReversible,
		ref:        "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation",
	},
	"disk": {
		title:      "Member of 'disk' group — raw block-device access",
		command:    "# find the root device (df /), then: debugfs /dev/sdaN  -> read /etc/shadow or write files as root",
		confidence: ConfMedium,
		blast:      BlastReversible,
		ref:        "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe",
	},
	"shadow": {
		title:      "Member of 'shadow' group — /etc/shadow is readable",
		command:    "cat /etc/shadow   # then crack root's hash offline (john/hashcat)",
		confidence: ConfMedium,
		blast:      BlastSafe,
		ref:        "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
	},
	"adm": {
		title:      "Member of 'adm' group — read system logs (hunt for secrets)",
		command:    "# grep -ri 'pass\\|secret\\|token' /var/log  — not direct root, but often yields creds",
		confidence: ConfLow,
		blast:      BlastSafe,
		ref:        "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
	},
}

func (g *GroupsCheck) Detect(c *Context) []Finding {
	username := currentUsername()
	gids := map[int]bool{}
	for _, gid := range c.GIDs {
		gids[gid] = true
	}
	gids[os.Getgid()] = true

	content, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil
	}

	var findings []Finding
	for _, name := range memberGroups(string(content), gids, username) {
		route, ok := groupRoutes[name]
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			Check:       g.Name(),
			Title:       route.title,
			Category:    "group",
			Confidence:  route.confidence,
			BlastRadius: route.blast,
			Evidence:    "current user is in group '" + name + "'",
			Command:     route.command,
			Reference:   route.ref,
		})
	}
	return findings
}

func currentUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

// memberGroups returns the names of groups the user belongs to, by matching
// either the process group-id set or the username against /etc/group members.
// Pure function for testability.
func memberGroups(groupFile string, gids map[int]bool, username string) []string {
	var names []string
	for _, line := range strings.Split(groupFile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		gid, _ := strconv.Atoi(fields[2])
		member := gids[gid]
		if !member && username != "" {
			for _, m := range strings.Split(fields[3], ",") {
				if strings.TrimSpace(m) == username {
					member = true
					break
				}
			}
		}
		if member {
			names = append(names, name)
		}
	}
	return names
}
