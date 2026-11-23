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
	"context"
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
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "golang.org/x/crypto/x509roots/fallback" // embedded CA roots (TV may lack a bundle)
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	version  = "1.1.2"
	ifName   = "nordtun"
	fwMark   = 51820
	table    = 51820
	rulePref = 31000
	stateDir = "/opt/nordtv"
	chain    = "NORDTV"
	natChain = "NORDTV_DNS"

	// runDir is root-only (0700, made by ensureRunDir) and in memory, so nothing in it outlives a restart and no
	// other user can plant a file there. Up to 1.1.1 these files were in /tmp, which anyone can write to.
	runDir     = "/dev/shm/nordtv.d"
	lockFile   = runDir + "/lock"   // write-locked (fcntl) by `nordtv up` from its first step to its exit
	pidFile    = runDir + "/pid"    // written once the tunnel is up
	serverFile = runDir + "/server" // what it connected to
	modeFile   = runDir + "/mode"   // full, or split and the AllowedIPs

	legacyPidFile = "/tmp/nordtv.pid" // nordtv 1.0.0 to 1.1.1, still running after an update

	// Without a handshake for retryAfter, the endpoint is set again (a host name looked up again first); without one
	// for giveUpAfter, `up` stops so that the next start (the Shard's "Keep connected") connects from scratch.
	retryAfter  = 5 * time.Minute
	giveUpAfter = 15 * time.Minute

	soMark = 0x24 // SO_MARK on Linux (named here so the tests also build on other systems)
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
	case "version":
		fmt.Println(version)
	case "lookup": // what a running tunnel does to find a host-name endpoint again (see lookupDirect)
		if len(os.Args) != 3 {
			usage()
		}
		ep, err := lookupDirect(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(ep)
	case "uninstall":
		cmdDown()
		os.RemoveAll(stateDir)
		os.RemoveAll(runDir)
		os.Remove("/dev/shm/nordtv") // where 1.0.0 to 1.1.1 ran from
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
  nordtv lookup HOST:PORT            look a server up past the tunnel and the DNS redirect, as a running tunnel does
  nordtv version | uninstall`)
	os.Exit(2)
}

// ---------------- NordVPN API ----------------

var httpc = &http.Client{Timeout: 20 * time.Second}

func apiGet(u string, token string, out any) error {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "nordtv/"+version)
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

// upLock is the lock file `nordtv up` holds for its whole life, kept in a variable so the garbage collector never
// closes it. Closing any descriptor of that file would drop the lock, so `up` itself never calls lockHolder.
var upLock *os.File

func cmdUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	token := fs.String("token", "", "NordVPN access token")
	confPath := fs.String("conf", "", "WireGuard .conf instead of NordVPN API")
	cc := fs.String("country", "", "country code, e.g. US, GB, IT")
	host := fs.String("server", "", "specific server hostname, e.g. us9591.nordvpn.com")
	ks := fs.Bool("killswitch", false, "block non-VPN internet traffic while running")
	deadline := fs.Duration("deadline", 0, "give up when not connected after this long (0: keep retrying for about 5 min)")
	fs.Parse(args)

	if err := ensureRunDir(); err != nil {
		log.Fatal(err)
	}
	if pid := legacyUp(); pid > 0 {
		log.Fatalf("an older nordtv is running (pid %d); run 'nordtv down' first", pid)
	}
	// The lock comes first, before any network call or rule: from here on `nordtv down` finds this process and stops
	// it, even while it is still waiting for the API or the endpoint, and a second `up` refuses to start, so two of
	// them can never remove each other's routes and chains.
	var err error
	if upLock, err = takeLock(); err != nil {
		log.Fatal(err)
	}
	removeRunFiles() // a crashed run's files; the lock says nothing else is running

	// While connecting, a signal, or the -deadline passing, stops this process at once, removing whatever it has set
	// up so far. The steps that change the system hold mu, so neither lands between two of them; once the tunnel is
	// up, the main loop takes the signals over and the deadline no longer counts. `nordtv start` passes a deadline,
	// so an `up` it started never connects after it reported a failure, even if `start` itself was killed.
	var (
		mu   sync.Mutex
		dev  *device.Device
		live bool
	)
	sig := make(chan os.Signal, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	var expire <-chan time.Time
	if *deadline > 0 {
		expire = time.After(*deadline)
	}
	go func() {
		for {
			code := 0
			select {
			case s := <-sig:
				mu.Lock()
				if live {
					mu.Unlock()
					quit <- s
					return
				}
				log.Printf("got %v while connecting, shutting down", s)
			case <-expire:
				mu.Lock()
				if live {
					mu.Unlock()
					expire = nil // a nil channel never fires: only signals from here on
					continue
				}
				log.Printf("not connected after %v, giving up", *deadline)
				code = 1
			}
			if dev != nil {
				dev.Close()
			}
			cleanup(true)
			removeRunFiles()
			os.Exit(code)
		}
	}()

	// Nothing else is running (the lock), so any rule left here is from a crash: remove it before the first network
	// call. A kill switch or DNS redirect left behind would block the API call and the endpoint lookup, and the TV
	// would stay offline instead of reconnecting.
	mu.Lock()
	cleanup(false)
	mu.Unlock()

	var c *wgConf
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
	epHost, _, _ := net.SplitHostPort(c.Endpoint)
	byName := net.ParseIP(epHost) == nil

	mu.Lock() // released when the tunnel is up
	cleanup(false)

	tdev, err := tun.CreateTUN(ifName, c.MTU)
	if err != nil {
		log.Fatal("create tun: ", err)
	}
	logger := device.NewLogger(device.LogLevelError, "wg: ")
	dev = device.NewDevice(tdev, conn.NewDefaultBind(), logger)
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
	// does this only when its .conf names a DNS server; otherwise the TV keeps its own. The WireGuard server itself
	// is let through first, in case it listens on port 53.
	dns := c.DNS
	if len(dns) == 0 && !split {
		dns = fallbackDNS
	}
	redirect := len(dns) > 0
	if redirect {
		shq("iptables", "-t", "nat", "-N", natChain)
		shq("iptables", "-t", "nat", "-A", natChain, "-o", "lo", "-j", "RETURN")
		shq(epReturn(ep, "iptables", "-t", "nat", "-A", natChain)...)
		for _, p := range []string{"udp", "tcp"} {
			shq("iptables", "-t", "nat", "-A", natChain, "-p", p, "--dport", "53", "-j", "DNAT", "--to-destination", dns[0]+":53")
		}
		shq("iptables", "-t", "nat", "-I", "OUTPUT", "1", "-j", natChain)
	}
	shq("ip", "route", "flush", "cache")

	killswitch := *ks && !split
	if *ks && split {
		// The kill switch would cut the internet that a split tunnel leaves outside on purpose.
		log.Print("kill switch not used: split tunnel (only AllowedIPs go through the VPN)")
	} else if *ks {
		// allow: loopback, tunnel, LAN, the WG endpoint (marked packets); drop everything else
		shq("iptables", "-N", chain)
		shq("iptables", "-A", chain, "-o", "lo", "-j", "RETURN")
		shq("iptables", "-A", chain, "-o", ifName, "-j", "RETURN")
		shq(epReturn(ep, "iptables", "-A", chain)...)
		shq("iptables", "-A", chain, "-m", "mark", "--mark", strconv.Itoa(fwMark), "-j", "RETURN") // if xt_mark exists
		for _, n := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"} {
			shq("iptables", "-A", chain, "-d", n, "-j", "RETURN")
		}
		shq("iptables", "-A", chain, "-j", "REJECT")
		shq("iptables", "-I", "OUTPUT", "1", "-j", chain)
		log.Print("kill switch enabled")
	}

	os.WriteFile(serverFile, []byte(c.Label+"\n"), 0600)
	mode := "full"
	if split {
		mode = "split " + strings.Join(c.Allowed, ",")
	}
	os.WriteFile(modeFile, []byte(mode+"\n"), 0600)
	os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600) // last: from here the state says "running"
	live = true
	mu.Unlock()
	log.Printf("tunnel %s up", ifName)

	tick := time.NewTicker(30 * time.Second)
	lastOK := time.Now() // the last handshake, or the start
	lastTry := lastOK
	for {
		select {
		case s := <-quit:
			log.Printf("got %v, shutting down", s)
			dev.Close()
			cleanup(true)
			removeRunFiles()
			return
		case <-dev.Wait():
			log.Print("device closed")
			cleanup(true)
			removeRunFiles()
			os.Exit(1)
		case <-tick.C:
			if hs := lastHandshake(dev); hs.After(lastOK) {
				lastOK = hs
			}
			// Wi-Fi reconnect / DHCP changes can wipe our rules; re-assert them.
			if !hasRule() {
				log.Print("routing rules missing, re-adding")
				for _, s := range steps[2:] {
					shq(s...)
				}
			}
			if time.Since(lastOK) > giveUpAfter {
				// Whatever is wrong (a server gone, a new address the lookup below could not find), a fresh start
				// fixes it: `up` removes every rule, looks the server up (NordVPN: asks for a new one) and connects.
				log.Printf("no handshake for %d min, stopping so that the next start connects from scratch", int(giveUpAfter/time.Minute))
				dev.Close()
				cleanup(true)
				removeRunFiles()
				os.Exit(1)
			}
			if time.Since(lastOK) > retryAfter && time.Since(lastTry) > retryAfter {
				lastTry = time.Now()
				if byName {
					// A host-name endpoint may have moved (a home server on a dynamic-DNS name): look it up again,
					// past the tunnel, the DNS redirect and the kill switch (lookupDirect). The kill switch and
					// the redirect let the new address through like the old one.
					nep, err := lookupDirect(c.Endpoint)
					if err != nil {
						log.Printf("endpoint lookup: %v", err)
					} else if !nep.IP.Equal(ep.IP) || nep.Port != ep.Port {
						log.Printf("endpoint moved to %s", nep)
						if killswitch {
							shq(epReturn(nep, "iptables", "-I", chain, "1")...)
						}
						if redirect {
							shq(epReturn(nep, "iptables", "-t", "nat", "-I", natChain, "1")...)
						}
						ep = nep
					}
				}
				log.Printf("no handshake for %d min, re-setting endpoint", int(time.Since(lastOK)/time.Minute))
				dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\n", pub, ep.String()))
			}
		}
	}
}

// epReturn is the iptables command cmd (its first words) that lets the WireGuard server's UDP through.
func epReturn(ep *net.UDPAddr, cmd ...string) []string {
	return append(append([]string{}, cmd...), "-p", "udp", "-d", ep.IP.String(), "--dport", strconv.Itoa(ep.Port), "-j", "RETURN")
}

// lookupDirect looks up a host-name endpoint while the tunnel is up but not working. A plain lookup fails then: the
// DNS redirect (NORDTV_DNS) sends it to the VPN's DNS server through the dead tunnel, and the routes and the kill
// switch would not let it out either. This one asks the TV's own DNS servers (/etc/resolv.conf) from sockets
// marked 51820, which the `not fwmark` rule routes outside the tunnel like WireGuard's own packets. For as long as
// the lookup runs, NORDTV_DNS and the kill switch let through UDP from that socket's port to that server's port 53,
// and nothing else: the TV's kernel has no `mark` match for iptables, so the port is what the rules can see.
func lookupDirect(endpoint string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("bad port in %q", endpoint)
	}
	var mu sync.Mutex
	var undo [][]string
	defer func() {
		mu.Lock()
		for _, u := range undo {
			shq(u...)
		}
		mu.Unlock()
	}()
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !strings.HasPrefix(network, "udp") {
			return nil, errors.New("no TCP lookups here")
		}
		d := net.Dialer{Control: markSocket}
		c, err := d.DialContext(ctx, "udp4", addr) // no packet is sent until the rules below are in place
		if err != nil {
			return nil, err
		}
		la, ra := c.LocalAddr().(*net.UDPAddr), c.RemoteAddr().(*net.UDPAddr)
		match := []string{"-p", "udp", "--sport", strconv.Itoa(la.Port), "-d", ra.IP.String(), "--dport", strconv.Itoa(ra.Port), "-j", "RETURN"}
		mu.Lock()
		for _, at := range [][]string{{"iptables", "-t", "nat"}, {"iptables"}} {
			ch := natChain
			if len(at) == 1 {
				ch = chain
			}
			add := append(append(append([]string{}, at...), "-I", ch, "1"), match...)
			if sh(add...) == nil { // the kill switch chain is missing when it is off
				undo = append(undo, append(append(append([]string{}, at...), "-D", ch), match...))
			}
		}
		mu.Unlock()
		return c, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ips, err := r.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPv4 address for %s", host)
	}
	return &net.UDPAddr{IP: ips[0], Port: pn}, nil
}

// markSocket gives a socket WireGuard's fwmark, so its packets take the main routing table, outside the tunnel.
func markSocket(network, address string, rc syscall.RawConn) error {
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMark, fwMark) }); err != nil {
		return err
	}
	return serr
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

// ensureRunDir makes runDir a real folder owned by root with mode 0700, replacing anything else found there (a
// file, a link, or a folder someone else made). /dev/shm is writable by everyone, but sticky: once root owns the
// folder no one else can remove or replace it.
func ensureRunDir() error {
	if fi, err := os.Lstat(runDir); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && fi.IsDir() && st.Uid == 0 {
			return os.Chmod(runDir, 0700)
		}
		if err := os.RemoveAll(runDir); err != nil {
			return err
		}
	}
	if err := os.Mkdir(runDir, 0700); err != nil {
		return fmt.Errorf("%s: %v", runDir, err)
	}
	return os.Chmod(runDir, 0700) // whatever the umask
}

// takeLock write-locks lockFile for this process, or says which `nordtv up` holds it.
func takeLock() (*os.File, error) { return takeLockAt(lockFile) }

func lockHolder() int { return lockHolderAt(lockFile) }

func takeLockAt(p string) (*os.File, error) {
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	lk := syscall.Flock_t{Type: syscall.F_WRLCK}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk); err != nil {
		f.Close()
		if pid := lockHolderAt(p); pid > 0 {
			return nil, fmt.Errorf("already running (pid %d); run 'nordtv down' first", pid)
		}
		return nil, fmt.Errorf("lock %s: %v", p, err)
	}
	return f, nil
}

// lockHolderAt is the pid of the process holding the lock on p, or 0. It only asks (F_GETLK), so a status read can
// never make an `up` fail to take the lock. A process that has exited holds no lock, crashed or not.
func lockHolderAt(p string) int {
	f, err := os.OpenFile(p, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0
	}
	defer f.Close()
	lk := syscall.Flock_t{Type: syscall.F_WRLCK}
	if syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk) != nil || lk.Type == syscall.F_UNLCK {
		return 0
	}
	return int(lk.Pid)
}

// legacyUp is the pid of a `nordtv up` from 1.0.0 to 1.1.1 (no lock, its pid in /tmp), or 0. A pid file in /tmp can
// be planted, so the process must really be `nordtv up`.
func legacyUp() int {
	b, err := os.ReadFile(legacyPidFile)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid <= 1 {
		return 0
	}
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || !isNordtvUp(cmdline) {
		return 0
	}
	return pid
}

// isNordtvUp tells whether a /proc/PID/cmdline is that of `nordtv up ...`.
func isNordtvUp(cmdline []byte) bool {
	args := strings.Split(string(cmdline), "\x00")
	return len(args) >= 2 && path.Base(args[0]) == "nordtv" && args[1] == "up"
}

// upPid is the pid of the running or connecting `nordtv up`, or 0.
func upPid() int {
	if pid := lockHolder(); pid > 0 {
		return pid
	}
	return legacyUp()
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// running: the tunnel is up. connecting: a `nordtv up` is still on its way there (API, endpoint lookup).
func running() bool {
	if lockHolder() > 0 {
		return exists(pidFile)
	}
	return legacyUp() > 0
}

func connecting() bool { return lockHolder() > 0 && !exists(pidFile) }

// readRun reads one of the files `up` writes (or, for an older one still running, its file in /tmp).
func readRun(p string) string {
	if lockHolder() == 0 && legacyUp() > 0 {
		p = "/tmp/nordtv." + path.Base(p)
	}
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

// runSince is when the tunnel came up.
func runSince() int64 {
	p := pidFile
	if lockHolder() == 0 && legacyUp() > 0 {
		p = legacyPidFile
	}
	if fi, err := os.Stat(p); err == nil {
		return fi.ModTime().Unix()
	}
	return 0
}

// removeRunFiles removes what `up` writes, the lock file excepted: removing it could split the lock in two.
func removeRunFiles() {
	for _, p := range []string{pidFile, serverFile, modeFile, legacyPidFile, "/tmp/nordtv.server", "/tmp/nordtv.mode"} {
		os.Remove(p)
	}
}

// cmdDown stops the `nordtv up` running or still connecting, and removes every rule, also when none is running.
func cmdDown() {
	if pid := upPid(); pid > 0 && syscall.Kill(pid, syscall.SIGTERM) == nil {
		if !waitDown(10 * time.Second) {
			syscall.Kill(pid, syscall.SIGKILL)
			waitDown(2 * time.Second)
		}
		fmt.Println("stopped")
	} else {
		fmt.Println("not running; cleaning up leftovers")
	}
	cleanup(false)
	removeRunFiles()
}

// waitDown waits until no `nordtv up` is left (an exited process holds no lock, so a zombie counts as gone).
func waitDown(d time.Duration) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if upPid() == 0 {
			return true
		}
	}
	return upPid() == 0
}

func cmdStatus() {
	if connecting() {
		fmt.Printf("nordtv: connecting (pid %d)\n", upPid())
		return
	}
	if !running() {
		fmt.Println("nordtv: down")
		return
	}
	fmt.Printf("nordtv: up (pid %d) server %s\n", upPid(), readRun(serverFile))
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
