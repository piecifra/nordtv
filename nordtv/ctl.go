package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const cfgFile = stateDir + "/config"

func cfgLoad() map[string]string {
	m := map[string]string{"COUNTRY": "IT", "KILLSWITCH": "1"}
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
	for _, key := range []string{"COUNTRY", "KILLSWITCH", "ENABLED", "AUTOSTART"} {
		if val, ok := m[key]; ok {
			fmt.Fprintf(&sb, "%s=%s\n", key, val)
		}
	}
	os.MkdirAll(stateDir, 0755)
	os.WriteFile(cfgFile, []byte(sb.String()), 0644)
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
	if running() {
		cmdDown()
	}
	c := cfgLoad()
	upArgs := []string{"up"}
	if c["COUNTRY"] != "" {
		upArgs = append(upArgs, "-country", c["COUNTRY"])
	}
	if c["KILLSWITCH"] == "1" {
		upArgs = append(upArgs, "-killswitch")
	}
	self, _ := os.Executable()
	logf, err := os.Create(stateDir + "/log")
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
		fmt.Fprintln(os.Stderr, "set country CC | set killswitch on|off | set token TOKEN")
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
	case "token":
		os.MkdirAll(stateDir, 0755)
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

type stateOut struct {
	Running    bool   `json:"running"`
	Pid        int    `json:"pid,omitempty"`
	Server     string `json:"server,omitempty"`
	Country    string `json:"country"`
	KillSwitch bool   `json:"killswitch"`
	Enabled    bool   `json:"enabled"`
	Autostart  bool   `json:"autostart"`
	HasToken   bool   `json:"hasToken"`
	Since      int64  `json:"since,omitempty"`
	PublicIP   string `json:"publicIp,omitempty"`
	City       string `json:"city,omitempty"`
	IPCountry  string `json:"ipCountry,omitempty"`
	Protected  *bool  `json:"protected,omitempty"`
	LastError  string `json:"lastError,omitempty"`
}

func cmdStateJSON(withIP bool) {
	c := cfgLoad()
	o := stateOut{Country: c["COUNTRY"], KillSwitch: c["KILLSWITCH"] == "1", Enabled: c["ENABLED"] == "1", Autostart: c["AUTOSTART"] != "0"}
	if b, err := os.ReadFile(stateDir + "/token"); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		o.HasToken = true
	}
	if running() {
		o.Running, o.Pid = true, readPid()
		b, _ := os.ReadFile("/tmp/nordtv.server")
		o.Server = strings.TrimSpace(string(b))
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
