// nordtv: self-contained WireGuard client for Tizen TVs (or any Linux): NordVPN (NordLynx, through its API) or
// any provider or server from a wg-quick .conf (IPv4 only).
//
//	nordtv up   [-token T | -conf wg.conf] [-country IT] [-server it123.nordvpn.com] [-killswitch]
//	nordtv down
//	nordtv status
//
// Runs wireguard-go in userspace on /dev/net/tun, then sets up policy routing
// (wg-quick style), DNS redirection and an optional kill switch via ip/iptables.
package main

import (
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

// fallbackDNS is used, through the tunnel, by a full-tunnel .conf without a DNS line (Quad9).
var fallbackDNS = []string{"9.9.9.9"}

type wgConf struct {
	PrivateKey string
	Address    string // CIDR
	DNS        []string
	MTU        int
	PeerPub    string
	Endpoint   string // host:port
	Keepalive  int
	Label      string
	PSK        string   // PresharedKey, optional
	Allowed    []string // IPv4 AllowedIPs, normalised; {"0.0.0.0/0"} is the full tunnel
}

// full is true when every IPv4 destination goes through the tunnel.
func (c *wgConf) full() bool {
	for _, a := range c.Allowed {
		if a == "0.0.0.0/0" {
			return true
		}
	}
	return false
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
	case "profile":
		cmdProfile(os.Args[2:])
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
  nordtv set provider nordvpn|wireguard | set profile NAME
  nordtv profile list | add NAME < file.conf | remove NAME   saved WireGuard configs
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
	req.Header.Set("User-Agent", "nordtv/1.1")
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
		Allowed:    []string{"0.0.0.0/0"},
	}, nil
}

// ---------------- wg-quick style .conf ----------------

func parseConf(path string) (*wgConf, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	label := path
	if dir, name, ok := strings.Cut(path, profileDir+"/"); ok && dir == "" {
		label = strings.TrimSuffix(name, ".conf") // a saved profile: its name
	}
	return parseConfText(string(b), label)
}

// parseConfText reads a wg-quick file with one [Peer]. IPv6 addresses, DNS servers and AllowedIPs are skipped: the
// tunnel is IPv4 and IPv6 egress is blocked while it runs. No AllowedIPs line means the full tunnel.
func parseConfText(text, label string) (*wgConf, error) {
	c := &wgConf{MTU: 1420, Keepalive: 25, Label: label}
	peers, sawAllowed := 0, false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if strings.EqualFold(line, "[peer]") {
			peers++
			continue
		}
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
					if ip, _, err := net.ParseCIDR(a); err != nil || ip.To4() == nil {
						return nil, fmt.Errorf("bad Address %q", a)
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
		case "presharedkey":
			c.PSK = v
		case "endpoint":
			c.Endpoint = v
		case "persistentkeepalive":
			c.Keepalive, _ = strconv.Atoi(v)
		case "allowedips":
			sawAllowed = true
			for _, a := range strings.Split(v, ",") {
				a = strings.TrimSpace(a)
				if !strings.Contains(a, ".") {
					continue // IPv6
				}
				if !strings.Contains(a, "/") {
					a += "/32"
				}
				_, n, err := net.ParseCIDR(a)
				if err != nil || n.IP.To4() == nil {
					return nil, fmt.Errorf("bad AllowedIPs entry %q", a)
				}
				c.Allowed = append(c.Allowed, n.String())
			}
		}
	}
	if peers > 1 {
		return nil, errors.New("conf has more than one [Peer]; only one is supported")
	}
	if c.PrivateKey == "" || c.PeerPub == "" || c.Endpoint == "" {
		return nil, errors.New("conf needs PrivateKey, Address, PublicKey and Endpoint")
	}
	if c.Address == "" {
		return nil, errors.New("conf has no IPv4 Address (IPv6-only servers are not supported)")
	}
	if !sawAllowed {
		c.Allowed = []string{"0.0.0.0/0"}
	} else if len(c.Allowed) == 0 {
		return nil, errors.New("conf has no IPv4 AllowedIPs (IPv6-only tunnels are not supported)")
	}
	// 0.0.0.0/1 + 128.0.0.0/1 is the usual "everything" written so it wins over a default route: same thing here.
	half := map[string]bool{}
	for _, a := range c.Allowed {
		half[a] = true
	}
	if half["0.0.0.0/1"] && half["128.0.0.0/1"] {
		c.Allowed = []string{"0.0.0.0/0"}
	}
	if c.full() {
		c.Allowed = []string{"0.0.0.0/0"}
	}
	if c.MTU < 1280 || c.MTU > 1500 {
		return nil, fmt.Errorf("MTU %d out of range (1280-1500)", c.MTU)
	}
	if c.Keepalive < 0 || c.Keepalive > 3600 {
		return nil, errors.New("PersistentKeepalive out of range")
	}
	for name, k := range map[string]string{"PrivateKey": c.PrivateKey, "PublicKey": c.PeerPub, "PresharedKey": c.PSK} {
		if k == "" && name == "PresharedKey" {
			continue
		}
		if _, err := b64hex(k); err != nil {
			return nil, fmt.Errorf("%s is not a WireGuard key", name)
		}
	}
	host, port, err := net.SplitHostPort(c.Endpoint)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("bad Endpoint %q (want host:port)", c.Endpoint)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return nil, errors.New("Endpoint is IPv6; only IPv4 servers are supported")
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
	// Nothing is running, so any rule left here is from a crash: remove it before the first network call. A kill
	// switch or DNS redirect left behind would block the API call and the endpoint lookup, and the TV would stay
	// offline instead of reconnecting.
	cleanup(false)

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
	var psk string
	if c.PSK != "" {
		if psk, err = b64hex(c.PSK); err != nil {
			log.Fatal("preshared key: ", err)
		}
	}
	// The endpoint may be a host name, and at boot DNS may not work yet.
	var ep *net.UDPAddr
	for i := 0; ; i++ {
		ep, err = net.ResolveUDPAddr("udp4", c.Endpoint)
		if err == nil || i >= 20 {
			break
		}
		log.Printf("endpoint: %v (retrying)", err)
		time.Sleep(15 * time.Second)
	}
	if err != nil {
		log.Fatal("endpoint: ", err)
	}
	split := !c.full()

	cleanup(false) // remove leftovers from a crash

	tdev, err := tun.CreateTUN(ifName, c.MTU)
	if err != nil {
		log.Fatal("create tun: ", err)
	}
	logger := device.NewLogger(device.LogLevelError, "wg: ")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	uapi := fmt.Sprintf("private_key=%s\nfwmark=%d\nreplace_peers=true\npublic_key=%s\n", priv, fwMark, pub)
	if psk != "" {
		uapi += "preshared_key=" + psk + "\n"
	}
	uapi += fmt.Sprintf("endpoint=%s\npersistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", ep.String(), c.Keepalive)
	for _, a := range c.Allowed {
		uapi += "allowed_ip=" + a + "\n"
	}
	if err := dev.IpcSet(uapi); err != nil {
		log.Fatal("configure: ", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatal("up: ", err)
	}

	// Table 51820 holds the tunnel's routes: the default route, or only the AllowedIPs of a split tunnel. The
	// suppress_prefixlength rule makes every specific route of the main table win, so the home network (the LAN's
	// own route) never goes into the tunnel; anything not in table 51820 falls through to the main table.
	steps := [][]string{
		{"ip", "addr", "add", c.Address, "dev", ifName},
		{"ip", "link", "set", ifName, "up", "mtu", strconv.Itoa(c.MTU)},
	}
	for _, a := range c.Allowed {
		dst := a
		if dst == "0.0.0.0/0" {
			dst = "default"
		}
		steps = append(steps, []string{"ip", "route", "add", dst, "dev", ifName, "table", strconv.Itoa(table)})
	}
	steps = append(steps,
		[]string{"ip", "rule", "add", "not", "fwmark", strconv.Itoa(fwMark), "table", strconv.Itoa(table), "pref", strconv.Itoa(rulePref + 1)},
		[]string{"ip", "rule", "add", "table", "main", "suppress_prefixlength", "0", "pref", strconv.Itoa(rulePref)},
	)
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

	// Force all DNS (the router from DHCP and resolvers hardcoded by apps) to the VPN resolver. A split tunnel
	// does this only when its .conf names a DNS server; otherwise the TV keeps its own.
	dns := c.DNS
	if len(dns) == 0 && !split {
		dns = fallbackDNS
	}
	if len(dns) > 0 {
		shq("iptables", "-t", "nat", "-N", natChain)
		for _, p := range []string{"udp", "tcp"} {
			shq("iptables", "-t", "nat", "-A", natChain, "-o", "lo", "-j", "RETURN")
			shq("iptables", "-t", "nat", "-A", natChain, "-p", p, "--dport", "53", "-j", "DNAT", "--to-destination", dns[0]+":53")
		}
		shq("iptables", "-t", "nat", "-I", "OUTPUT", "1", "-j", natChain)
	}
	shq("ip", "route", "flush", "cache")

	if *ks && split {
		// The kill switch would cut the internet that a split tunnel leaves outside on purpose.
		log.Print("kill switch not used: split tunnel (only AllowedIPs go through the VPN)")
	} else if *ks {
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
	mode := "full"
	if split {
		mode = "split " + strings.Join(c.Allowed, ",")
	}
	os.WriteFile("/tmp/nordtv.mode", []byte(mode+"\n"), 0644)
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
			os.Remove("/tmp/nordtv.mode")
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
				// A host-name endpoint may have moved: resolve it again (the kill switch follows the new address).
				if nep, err := net.ResolveUDPAddr("udp4", c.Endpoint); err == nil && !nep.IP.Equal(ep.IP) {
					log.Printf("endpoint moved to %s", nep)
					if *ks && !split {
						shq("iptables", "-I", chain, "1", "-p", "udp", "-d", nep.IP.String(), "--dport", strconv.Itoa(nep.Port), "-j", "RETURN")
					}
					ep = nep
				}
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
	fmt.Printf("settings: provider=%s profile=%s country=%s killswitch=%s\n", c["PROVIDER"], c["PROFILE"], c["COUNTRY"], c["KILLSWITCH"])
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
