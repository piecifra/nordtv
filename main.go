// nordtv: self-contained NordLynx (WireGuard) client for Tizen TVs (or any Linux).
//
//   nordtv up   [-token T | -conf wg.conf] [-country IT] [-server it123.nordvpn.com] [-killswitch]
//   nordtv down
//   nordtv status
//
// Runs wireguard-go in userspace on /dev/net/tun, then sets up policy routing
// (wg-quick style), DNS redirection and an optional kill switch via ip/iptables.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "golang.org/x/crypto/x509roots/fallback" // embedded CA roots (TV may lack a bundle)
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	ifName   = "nordtun"
	fwMark   = 51820
	table    = 51820
	rulePref = 31000
	pidFile  = "/tmp/nordtv.pid"
	stateDir = "/opt/nordtv"
	chain    = "NORDTV"
	natChain = "NORDTV_DNS"
)

var nordDNS = []string{"103.86.96.100", "103.86.99.100"}

type wgConf struct {
	PrivateKey string
	Address    string // CIDR
	DNS        []string
	MTU        int
	PeerPub    string
	Endpoint   string // host:port
	Keepalive  int
	Label      string
}

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
	}
	secureState()
	switch os.Args[1] {
	case "up":
		cmdUp(os.Args[2:])
	case "down":
		cmdDown()
	case "status":
		if len(os.Args) > 2 && os.Args[2] == "-json" {
			cmdStateJSON(true)
		} else {
			cmdStatus()
		}
	case "state":
		cmdStateJSON(false)
	case "verify":
		cmdVerify()
	case "countries":
		cmdCountries()
	case "start", "restart":
		cmdStart(os.Args[2:])
	case "stop":
		cfgSet("ENABLED", "0")
		cmdDown()
	case "set":
		cmdSet(os.Args[2:])
	case "log":
		cmdLog(os.Args[2:])
	case "uninstall":
		cmdDown()
		os.RemoveAll(stateDir)
		os.Remove("/dev/shm/nordtv")
		fmt.Println("removed", stateDir)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  nordtv up [-token TOKEN | -conf file.conf] [-country CODE] [-server HOST] [-killswitch]
            (token may also be stored in /opt/nordtv/token)
  nordtv down
  nordtv status
  nordtv countries

managed mode (settings in /opt/nordtv/config):
  nordtv start [CC] [--no-ks|--ks]   start in background (optionally change country/kill switch)
  nordtv stop | restart
  nordtv set country CC | set killswitch on|off | set token TOKEN
  nordtv log [N]
  nordtv state | status -json        machine-readable state (status adds public IP)
  nordtv verify                      check the saved token against NordVPN
  nordtv uninstall`)
	os.Exit(2)
}

// ---------------- NordVPN API ----------------

var httpc = &http.Client{Timeout: 20 * time.Second}

func apiGet(u string, token string, out any) error {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "nordtv/1.0")
	if token != "" {
		req.SetBasicAuth("token", token)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d: %s", u, resp.StatusCode, truncate(string(body), 200))
	}
	return json.Unmarshal(body, out)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type country struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Code string `json:"code"`
}

type server struct {
	Hostname     string `json:"hostname"`
	Station      string `json:"station"`
	Load         int    `json:"load"`
	Technologies []struct {
		Identifier string `json:"identifier"`
		Metadata   []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"metadata"`
	} `json:"technologies"`
}

func (s server) wgPub() string {
	for _, t := range s.Technologies {
		if t.Identifier == "wireguard_udp" {
			for _, m := range t.Metadata {
				if m.Name == "public_key" {
					return m.Value
				}
			}
		}
	}
	return ""
}

func countries() ([]country, error) {
	var cs []country
	err := apiGet("https://api.nordvpn.com/v1/servers/countries", "", &cs)
	return cs, err
}

func cmdCountries() {
	cs, err := countries()
	if err != nil {
		log.Fatal(err)
	}
	for _, c := range cs {
		fmt.Printf("%s\t%s\n", c.Code, c.Name)
	}
}

func nordConf(token, countryCode, host string) (*wgConf, error) {
	var cred struct {
		Key string `json:"nordlynx_private_key"`
	}
	if err := apiGet("https://api.nordvpn.com/v1/users/services/credentials", token, &cred); err != nil {
		return nil, fmt.Errorf("fetching NordLynx key (check token): %w", err)
	}
	if cred.Key == "" {
		return nil, errors.New("API returned no nordlynx_private_key")
	}

	var srv server
	if host != "" {
		var list []server
		q := "https://api.nordvpn.com/v1/servers?limit=1&filters[hostname]=" + url.QueryEscape(host)
		if err := apiGet(q, "", &list); err != nil {
			return nil, err
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("server %s not found", host)
		}
		srv = list[0]
	} else {
		q := "https://api.nordvpn.com/v1/servers/recommendations?limit=5&filters[servers_technologies][identifier]=wireguard_udp"
		if countryCode != "" {
			cs, err := countries()
			if err != nil {
				return nil, err
			}
			id := 0
			for _, c := range cs {
				if strings.EqualFold(c.Code, countryCode) {
					id = c.ID
				}
			}
			if id == 0 {
				return nil, fmt.Errorf("unknown country code %q (see: nordtv countries)", countryCode)
			}
			q += "&filters[country_id]=" + strconv.Itoa(id)
		}
		var list []server
		if err := apiGet(q, "", &list); err != nil {
			return nil, err
		}
		for _, s := range list {
			if s.wgPub() != "" {
				srv = s
				break
			}
		}
		if srv.Hostname == "" {
			return nil, errors.New("no NordLynx server recommended")
		}
	}
	if srv.wgPub() == "" {
		return nil, fmt.Errorf("server %s has no NordLynx key", srv.Hostname)
	}
	return &wgConf{
		PrivateKey: cred.Key,
		Address:    "10.5.0.2/32",
		DNS:        nordDNS,
		MTU:        1420,
		PeerPub:    srv.wgPub(),
		Endpoint:   net.JoinHostPort(srv.Station, "51820"),
		Keepalive:  25,
		Label:      fmt.Sprintf("%s (load %d%%)", srv.Hostname, srv.Load),
	}, nil
}

// ---------------- wg-quick style .conf ----------------

func parseConf(path string) (*wgConf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c := &wgConf{MTU: 1420, Keepalive: 25, Label: path}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "privatekey":
			c.PrivateKey = v
		case "address":
			for _, a := range strings.Split(v, ",") {
				a = strings.TrimSpace(a)
				if strings.Contains(a, ".") && c.Address == "" {
					if !strings.Contains(a, "/") {
						a += "/32"
					}
					c.Address = a
				}
			}
		case "dns":
			for _, d := range strings.Split(v, ",") {
				if ip := net.ParseIP(strings.TrimSpace(d)); ip != nil && ip.To4() != nil {
					c.DNS = append(c.DNS, ip.String())
				}
			}
		case "mtu":
			c.MTU, _ = strconv.Atoi(v)
		case "publickey":
			c.PeerPub = v
		case "endpoint":
			c.Endpoint = v
		case "persistentkeepalive":
			c.Keepalive, _ = strconv.Atoi(v)
		}
	}
	if c.PrivateKey == "" || c.PeerPub == "" || c.Endpoint == "" || c.Address == "" {
		return nil, errors.New("conf needs PrivateKey, Address, PublicKey, Endpoint")
	}
	return c, nil
}

// ---------------- up ----------------

func b64hex(k string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("bad key")
	}
	return hex.EncodeToString(b), nil
}

func sh(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func shq(args ...string) { _ = sh(args...) } // best effort

func cmdUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	token := fs.String("token", "", "NordVPN access token")
	confPath := fs.String("conf", "", "WireGuard .conf instead of NordVPN API")
	cc := fs.String("country", "", "country code, e.g. US, GB, IT")
	host := fs.String("server", "", "specific server hostname, e.g. us9591.nordvpn.com")
	ks := fs.Bool("killswitch", false, "block non-VPN internet traffic while running")
	fs.Parse(args)

	if pid := readPid(); pid > 0 && syscall.Kill(pid, 0) == nil {
		log.Fatalf("already running (pid %d); run 'nordtv down' first", pid)
	}

	var c *wgConf
	var err error
	if *confPath != "" {
		c, err = parseConf(*confPath)
	} else {
		if *token == "" {
			if b, e := os.ReadFile(stateDir + "/token"); e == nil {
				*token = strings.TrimSpace(string(b))
			}
		}
		if *token == "" {
			log.Fatal("need -token (or /opt/nordtv/token) or -conf")
		}
		// retry: at boot Wi-Fi may not be up yet
		for i := 0; ; i++ {
			c, err = nordConf(*token, *cc, *host)
			if err == nil || i >= 20 || strings.Contains(err.Error(), "HTTP 401") {
				break
			}
			log.Printf("api: %v (retrying)", err)
			time.Sleep(15 * time.Second)
		}
	}
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("server: %s endpoint %s", c.Label, c.Endpoint)

	priv, err := b64hex(c.PrivateKey)
	if err != nil {
		log.Fatal("private key: ", err)
	}
	pub, err := b64hex(c.PeerPub)
	if err != nil {
		log.Fatal("peer key: ", err)
	}
	ep, err := net.ResolveUDPAddr("udp4", c.Endpoint)
	if err != nil {
		log.Fatal("endpoint: ", err)
	}

	cleanup(false) // remove leftovers from a crash

	tdev, err := tun.CreateTUN(ifName, c.MTU)
	if err != nil {
		log.Fatal("create tun: ", err)
	}
	logger := device.NewLogger(device.LogLevelError, "wg: ")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	uapi := fmt.Sprintf("private_key=%s\nfwmark=%d\nreplace_peers=true\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\n",
		priv, fwMark, pub, ep.String(), c.Keepalive)
	if err := dev.IpcSet(uapi); err != nil {
		log.Fatal("configure: ", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatal("up: ", err)
	}

	steps := [][]string{
		{"ip", "addr", "add", c.Address, "dev", ifName},
		{"ip", "link", "set", ifName, "up", "mtu", strconv.Itoa(c.MTU)},
		{"ip", "route", "add", "default", "dev", ifName, "table", strconv.Itoa(table)},
		{"ip", "rule", "add", "not", "fwmark", strconv.Itoa(fwMark), "table", strconv.Itoa(table), "pref", strconv.Itoa(rulePref + 1)},
		{"ip", "rule", "add", "table", "main", "suppress_prefixlength", "0", "pref", strconv.Itoa(rulePref)},
	}
	for _, s := range steps {
		if err := sh(s...); err != nil {
			dev.Close()
			cleanup(false)
			log.Fatal(err)
		}
	}
	// IPv6 is not tunnelled: drop global v6 egress to avoid leaks
	shq("ip6tables", "-N", chain)
	shq("ip6tables", "-A", chain, "-o", "lo", "-j", "RETURN")
	shq("ip6tables", "-A", chain, "-d", "fe80::/10", "-j", "RETURN")
	shq("ip6tables", "-A", chain, "-d", "ff00::/8", "-j", "RETURN")
	shq("ip6tables", "-A", chain, "-j", "REJECT")
	shq("ip6tables", "-I", "OUTPUT", "1", "-j", chain)

	// Force all DNS (the router from DHCP and resolvers hardcoded by apps) to the VPN resolver
	dns := c.DNS
	if len(dns) == 0 {
		dns = nordDNS
	}
	shq("iptables", "-t", "nat", "-N", natChain)
	for _, p := range []string{"udp", "tcp"} {
		shq("iptables", "-t", "nat", "-A", natChain, "-o", "lo", "-j", "RETURN")
		shq("iptables", "-t", "nat", "-A", natChain, "-p", p, "--dport", "53", "-j", "DNAT", "--to-destination", dns[0]+":53")
	}
	shq("iptables", "-t", "nat", "-I", "OUTPUT", "1", "-j", natChain)
	shq("ip", "route", "flush", "cache")

	if *ks {
		// allow: loopback, tunnel, LAN, the WG endpoint (marked packets); drop everything else
		shq("iptables", "-N", chain)
		shq("iptables", "-A", chain, "-o", "lo", "-j", "RETURN")
		shq("iptables", "-A", chain, "-o", ifName, "-j", "RETURN")
		shq("iptables", "-A", chain, "-p", "udp", "-d", ep.IP.String(), "--dport", strconv.Itoa(ep.Port), "-j", "RETURN")
		shq("iptables", "-A", chain, "-m", "mark", "--mark", strconv.Itoa(fwMark), "-j", "RETURN") // if xt_mark exists
		for _, n := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"} {
			shq("iptables", "-A", chain, "-d", n, "-j", "RETURN")
		}
		shq("iptables", "-A", chain, "-j", "REJECT")
		shq("iptables", "-I", "OUTPUT", "1", "-j", chain)
		log.Print("kill switch enabled")
	}

	os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644)
	os.WriteFile("/tmp/nordtv.server", []byte(c.Label+"\n"), 0644)
	log.Printf("tunnel %s up", ifName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	tick := time.NewTicker(30 * time.Second)
	var lastOK time.Time = time.Now()
	for {
		select {
		case s := <-sig:
			log.Printf("got %v, shutting down", s)
			dev.Close()
			cleanup(true)
			os.Remove(pidFile)
			os.Remove("/tmp/nordtv.server")
			return
		case <-dev.Wait():
			log.Print("device closed")
			cleanup(true)
			os.Exit(1)
		case <-tick.C:
			hs := lastHandshake(dev)
			if !hs.IsZero() {
				lastOK = hs
			}
			// Wi-Fi reconnect / DHCP changes can wipe our rules; re-assert them.
			if !hasRule() {
				log.Print("routing rules missing, re-adding")
				for _, s := range steps[2:] {
					shq(s...)
				}
			}
			if time.Since(lastOK) > 5*time.Minute {
				log.Print("no handshake for 5 min, re-setting endpoint")
				dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\n", pub, ep.String()))
				lastOK = time.Now()
			}
		}
	}
}

func lastHandshake(dev *device.Device) time.Time {
	s, err := dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	var sec int64
	for _, l := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(l, "last_handshake_time_sec="); ok {
			sec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

func hasRule() bool {
	out, _ := exec.Command("ip", "rule").Output()
	return strings.Contains(string(out), "lookup "+strconv.Itoa(table)) ||
		strings.Contains(string(out), "lookup 0xca6c")
}

func cleanup(verbose bool) {
	for i := 0; i < 3; i++ {
		shq("ip", "rule", "del", "pref", strconv.Itoa(rulePref))
		shq("ip", "rule", "del", "pref", strconv.Itoa(rulePref+1))
	}
	shq("ip", "route", "flush", "table", strconv.Itoa(table))
	shq("ip", "link", "del", ifName)
	for range 3 {
		shq("iptables", "-D", "OUTPUT", "-j", chain)
		shq("ip6tables", "-D", "OUTPUT", "-j", chain)
		shq("iptables", "-t", "nat", "-D", "OUTPUT", "-j", natChain)
	}
	shq("iptables", "-F", chain)
	shq("iptables", "-X", chain)
	shq("ip6tables", "-F", chain)
	shq("ip6tables", "-X", chain)
	shq("iptables", "-t", "nat", "-F", natChain)
	shq("iptables", "-t", "nat", "-X", natChain)
	shq("ip", "route", "flush", "cache")
	if verbose {
		log.Print("routes and firewall restored")
	}
}

func readPid() int {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return p
}

func cmdDown() {
	pid := readPid()
	if pid > 0 && syscall.Kill(pid, syscall.SIGTERM) == nil {
		for i := 0; i < 50 && syscall.Kill(pid, 0) == nil; i++ {
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Println("stopped")
	} else {
		fmt.Println("not running; cleaning up leftovers")
	}
	cleanup(false)
	os.Remove(pidFile)
}

func cmdStatus() {
	pid := readPid()
	if pid == 0 || syscall.Kill(pid, 0) != nil {
		fmt.Println("nordtv: down")
		return
	}
	srv, _ := os.ReadFile("/tmp/nordtv.server")
	fmt.Printf("nordtv: up (pid %d) server %s", pid, srv)
	c := cfgLoad()
	fmt.Printf("settings: country=%s killswitch=%s\n", c["COUNTRY"], c["KILLSWITCH"])
	resp, err := httpc.Get("https://api.nordvpn.com/v1/helpers/ips/insights")
	if err == nil {
		defer resp.Body.Close()
		var ins struct {
			IP        string `json:"ip"`
			Country   string `json:"country"`
			City      string `json:"city"`
			Protected bool   `json:"protected"`
		}
		json.NewDecoder(resp.Body).Decode(&ins)
		fmt.Printf("public IP %s (%s, %s) protected=%v\n", ins.IP, ins.City, ins.Country, ins.Protected)
	}
}
