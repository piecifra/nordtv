package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	cfgFile    = stateDir + "/config"
	profileDir = stateDir + "/profiles" // saved WireGuard configs, <name>.conf, 0600
	maxConf    = 16 << 10
	maxProfile = 20
)

var profileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)

func cfgLoad() map[string]string {
	m := map[string]string{"COUNTRY": "IT", "KILLSWITCH": "1", "PROVIDER": "nordvpn"}
	b, _ := os.ReadFile(cfgFile)
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			m[k] = v
		}
	}
	return m
}

func cfgSet(k, v string) {
	m := cfgLoad()
	m[k] = v
	var sb strings.Builder
	for _, key := range []string{"PROVIDER", "PROFILE", "COUNTRY", "KILLSWITCH", "ENABLED", "AUTOSTART"} {
		if val, ok := m[key]; ok {
			fmt.Fprintf(&sb, "%s=%s\n", key, val)
		}
	}
	os.MkdirAll(stateDir, 0700)
	os.WriteFile(cfgFile, []byte(sb.String()), 0600)
}

func running() bool {
	pid := readPid()
	return pid > 0 && syscall.Kill(pid, 0) == nil
}

func cmdStart(args []string) {
	for _, a := range args {
		switch {
		case a == "--no-ks":
			cfgSet("KILLSWITCH", "0")
		case a == "--ks":
			cfgSet("KILLSWITCH", "1")
		case len(a) == 2:
			cfgSet("COUNTRY", strings.ToUpper(a))
		default:
			fmt.Fprintln(os.Stderr, "unknown arg", a)
			os.Exit(2)
		}
	}
	c := cfgLoad()
	upArgs := []string{"up"}
	if c["PROVIDER"] == "wireguard" {
		// Check before taking a running tunnel down: a bad choice must not leave the TV without its VPN.
		if !profileName.MatchString(c["PROFILE"]) {
			fail(1, "no WireGuard profile chosen (nordtv set profile NAME)")
		}
		if _, err := parseConf(profilePath(c["PROFILE"])); err != nil {
			fail(1, "profile "+c["PROFILE"]+":", err)
		}
		upArgs = append(upArgs, "-conf", profilePath(c["PROFILE"]))
	} else if c["COUNTRY"] != "" {
		upArgs = append(upArgs, "-country", c["COUNTRY"])
	}
	if c["KILLSWITCH"] == "1" {
		upArgs = append(upArgs, "-killswitch")
	}
	if running() {
		cmdDown()
	}
	self, _ := os.Executable()
	logf, err := os.OpenFile(stateDir+"/log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cmd := exec.Command(self, upArgs...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		os.Exit(1)
	}
	cmd.Process.Release()
	cfgSet("ENABLED", "1")
	for i := 0; i < 30 && !running(); i++ {
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)
	cmdStatus()
	if !running() {
		cmdLog([]string{"10"})
		os.Exit(1)
	}
}

func cmdSet(a []string) {
	if len(a) != 2 {
		fmt.Fprintln(os.Stderr, "set country CC | set killswitch on|off | set autostart on|off | set token TOKEN | set provider nordvpn|wireguard | set profile NAME")
		os.Exit(2)
	}
	switch a[0] {
	case "country":
		cfgSet("COUNTRY", strings.ToUpper(a[1]))
	case "killswitch", "autostart":
		v, ok := map[string]string{"on": "1", "off": "0"}[a[1]]
		if !ok {
			fmt.Fprintln(os.Stderr, "on|off")
			os.Exit(2)
		}
		cfgSet(strings.ToUpper(a[0]), v)
	case "provider":
		if a[1] != "nordvpn" && a[1] != "wireguard" {
			fail(2, "nordvpn|wireguard")
		}
		cfgSet("PROVIDER", a[1])
	case "profile":
		if _, err := os.Stat(profilePath(a[1])); !profileName.MatchString(a[1]) || err != nil {
			fail(1, "no saved profile", a[1], "(nordtv profile list)")
		}
		cfgSet("PROFILE", a[1])
	case "token":
		os.MkdirAll(stateDir, 0700)
		os.WriteFile(stateDir+"/token", []byte(a[1]+"\n"), 0600)
	default:
		fmt.Fprintln(os.Stderr, "unknown setting", a[0])
		os.Exit(2)
	}
	fmt.Println("saved; apply with: nordtv restart")
}

func cmdLog(a []string) {
	n := 30
	if len(a) > 0 {
		n, _ = strconv.Atoi(a[0])
	}
	b, _ := os.ReadFile(stateDir + "/log")
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if !strings.Contains(l, "sendmmsg") {
			keep = append(keep, l)
		}
	}
	if len(keep) > n {
		keep = keep[len(keep)-n:]
	}
	fmt.Println(strings.Join(keep, "\n"))
}

func profilePath(name string) string { return profileDir + "/" + name + ".conf" }

// profile is what the state shows of a saved config: never its keys.
type profile struct {
	Name     string   `json:"name"`
	Endpoint string   `json:"endpoint,omitempty"`
	Address  string   `json:"address,omitempty"`
	Split    bool     `json:"split"`
	Allowed  []string `json:"allowedIps"`
	DNS      []string `json:"dns"`
	Error    string   `json:"error,omitempty"`
}

func profiles() []profile {
	entries, _ := os.ReadDir(profileDir)
	out := []profile{}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".conf")
		if !ok || !e.Type().IsRegular() || !profileName.MatchString(name) {
			continue
		}
		p := profile{Name: name, Allowed: []string{}, DNS: []string{}}
		if c, err := parseConf(profilePath(name)); err != nil {
			p.Error = err.Error()
		} else {
			p.Endpoint, p.Address, p.Split, p.Allowed = c.Endpoint, c.Address, !c.full(), c.Allowed
			if c.DNS != nil {
				p.DNS = c.DNS
			}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func fail(code int, msg ...any) {
	fmt.Fprintln(os.Stderr, msg...)
	os.Exit(code)
}

// nordtv profile list | add NAME (the .conf on stdin) | remove NAME
func cmdProfile(a []string) {
	switch {
	case len(a) == 1 && a[0] == "list":
		json.NewEncoder(os.Stdout).Encode(map[string]any{"profiles": profiles()})
	case len(a) == 2 && a[0] == "add":
		name := a[1]
		if !profileName.MatchString(name) {
			fail(2, "profile name: letters, digits, - and _, up to 32")
		}
		b, err := io.ReadAll(io.LimitReader(os.Stdin, maxConf+1))
		if err != nil || len(b) > maxConf {
			fail(1, "conf too large or unreadable")
		}
		if _, err := parseConfText(string(b), name); err != nil {
			fail(1, err)
		}
		if _, err := os.Stat(profilePath(name)); err != nil && len(profiles()) >= maxProfile {
			fail(1, "at most", maxProfile, "profiles")
		}
		os.MkdirAll(profileDir, 0700)
		os.Chmod(profileDir, 0700)
		tmp := profilePath(name) + ".new"
		if err := os.WriteFile(tmp, b, 0600); err != nil {
			fail(1, err)
		}
		if err := os.Rename(tmp, profilePath(name)); err != nil {
			os.Remove(tmp)
			fail(1, err)
		}
		fmt.Println("saved profile", name)
	case len(a) == 2 && a[0] == "remove":
		if !profileName.MatchString(a[1]) {
			fail(2, "bad profile name")
		}
		if err := os.Remove(profilePath(a[1])); err != nil {
			fail(1, "no saved profile", a[1])
		}
		if c := cfgLoad(); c["PROFILE"] == a[1] {
			cfgSet("PROFILE", "")
		}
		fmt.Println("removed profile", a[1])
	default:
		fail(2, "profile list | add NAME < file.conf | remove NAME")
	}
}

type stateOut struct {
	Provider   string    `json:"provider"`
	Profile    string    `json:"profile"`
	Profiles   []profile `json:"profiles"`
	Ready      bool      `json:"ready"` // what the provider needs is saved: a token, or a valid chosen profile
	Mode       string    `json:"mode,omitempty"`
	Running    bool      `json:"running"`
	Pid        int       `json:"pid,omitempty"`
	Server     string    `json:"server,omitempty"`
	Country    string    `json:"country"`
	KillSwitch bool      `json:"killswitch"`
	Enabled    bool      `json:"enabled"`
	Autostart  bool      `json:"autostart"`
	HasToken   bool      `json:"hasToken"`
	Since      int64     `json:"since,omitempty"`
	PublicIP   string    `json:"publicIp,omitempty"`
	City       string    `json:"city,omitempty"`
	IPCountry  string    `json:"ipCountry,omitempty"`
	Protected  *bool     `json:"protected,omitempty"`
	LastError  string    `json:"lastError,omitempty"`
}

func cmdStateJSON(withIP bool) {
	c := cfgLoad()
	o := stateOut{Provider: c["PROVIDER"], Profile: c["PROFILE"], Profiles: profiles(), Country: c["COUNTRY"], KillSwitch: c["KILLSWITCH"] == "1", Enabled: c["ENABLED"] == "1", Autostart: c["AUTOSTART"] != "0"}
	if b, err := os.ReadFile(stateDir + "/token"); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		o.HasToken = true
	}
	if o.Provider == "wireguard" {
		for _, p := range o.Profiles {
			if p.Name == o.Profile && p.Error == "" {
				o.Ready = true
			}
		}
	} else {
		o.Ready = o.HasToken
	}
	if running() {
		o.Running, o.Pid = true, readPid()
		b, _ := os.ReadFile("/tmp/nordtv.server")
		o.Server = strings.TrimSpace(string(b))
		m, _ := os.ReadFile("/tmp/nordtv.mode")
		o.Mode = strings.TrimSpace(string(m))
		if fi, err := os.Stat(pidFile); err == nil {
			o.Since = fi.ModTime().Unix()
		}
	} else {
		// last fatal line of the log, if the tunnel stopped on its own
		b, _ := os.ReadFile(stateDir + "/log")
		if strings.Contains(string(b), "shutting down") { // stopped on request: nothing to report
			b = nil
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		for i := len(lines) - 1; i >= 0 && i >= len(lines)-5; i-- {
			l := lines[i]
			if l != "" && !strings.Contains(l, "sendmmsg") && !strings.Contains(l, "shutting down") && !strings.Contains(l, "restored") && !strings.Contains(l, "tunnel ") {
				o.LastError = l
				break
			}
		}
	}
	if withIP {
		hc := &http.Client{Timeout: 6 * time.Second}
		if resp, err := hc.Get("https://api.nordvpn.com/v1/helpers/ips/insights"); err == nil {
			var ins struct {
				IP        string `json:"ip"`
				Country   string `json:"country"`
				City      string `json:"city"`
				Protected bool   `json:"protected"`
			}
			if json.NewDecoder(resp.Body).Decode(&ins) == nil {
				o.PublicIP, o.City, o.IPCountry, o.Protected = ins.IP, ins.City, ins.Country, &ins.Protected
			}
			resp.Body.Close()
		}
	}
	json.NewEncoder(os.Stdout).Encode(o)
}

func cmdVerify() {
	out := map[string]any{"ok": false}
	b, err := os.ReadFile(stateDir + "/token")
	tok := strings.TrimSpace(string(b))
	if err != nil || tok == "" {
		out["error"] = "no token saved"
	} else {
		var cred struct {
			Key string `json:"nordlynx_private_key"`
		}
		if err := apiGet("https://api.nordvpn.com/v1/users/services/credentials", tok, &cred); err != nil {
			if strings.Contains(err.Error(), "HTTP 401") {
				out["error"] = "token rejected by NordVPN"
			} else {
				out["error"] = "could not reach NordVPN"
			}
		} else if cred.Key == "" {
			out["error"] = "account has no NordLynx key"
		} else {
			out["ok"] = true
		}
	}
	json.NewEncoder(os.Stdout).Encode(out)
}

// secureState keeps /opt/nordtv root-only: root runs the binary from here and the token is a credential.
// Folder 0700, everything in it 0600, the binary 0700. Files created later already get these modes.
func secureState() {
	if os.Geteuid() != 0 {
		return
	}
	if fi, err := os.Stat(stateDir); err != nil || !fi.IsDir() {
		return
	}
	os.Chmod(stateDir, 0700)
	os.Chmod(profileDir, 0700)
	if pe, err := os.ReadDir(profileDir); err == nil {
		for _, e := range pe {
			if e.Type().IsRegular() {
				os.Lchown(profileDir+"/"+e.Name(), 0, 0)
				os.Chmod(profileDir+"/"+e.Name(), 0600)
			}
		}
	}
	entries, _ := os.ReadDir(stateDir)
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		p := stateDir + "/" + e.Name()
		os.Lchown(p, 0, 0)
		if e.Name() == "nordtv" || strings.HasSuffix(e.Name(), ".new") {
			os.Chmod(p, 0700)
		} else {
			os.Chmod(p, 0600)
		}
	}
}
