package main

import (
	"reflect"
	"strings"
	"testing"
)

// Keys are 32 bytes of base64; these are made up.
const (
	kPriv = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	kPub  = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
	kPSK  = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
)

func conf(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func TestFullTunnelMullvadStyle(t *testing.T) {
	c, err := parseConfText(conf(
		"[Interface]", "# Device: Happy Fox", "PrivateKey = "+kPriv,
		"Address = 10.68.12.34/32,fc00:bbbb:bbbb:bb01::5:c21/128", "DNS = 10.64.0.1",
		"", "[Peer]", "PublicKey = "+kPub, "AllowedIPs = 0.0.0.0/0,::0/0", "Endpoint = 185.65.134.82:51820"), "mullvad-it")
	if err != nil {
		t.Fatal(err)
	}
	if !c.full() || !reflect.DeepEqual(c.Allowed, []string{"0.0.0.0/0"}) {
		t.Fatalf("want full tunnel, got %v", c.Allowed)
	}
	if c.Address != "10.68.12.34/32" || !reflect.DeepEqual(c.DNS, []string{"10.64.0.1"}) || c.MTU != 1420 || c.Keepalive != 25 {
		t.Fatalf("got %+v", c)
	}
}

func TestHalvesAreFull(t *testing.T) {
	c, err := parseConfText(conf("[Interface]", "PrivateKey="+kPriv, "Address=10.2.0.2/32", "[Peer]", "PublicKey="+kPub,
		"AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1", "Endpoint=vpn.example.net:51820"), "x")
	if err != nil || !c.full() {
		t.Fatalf("want full, got %v %v", c, err)
	}
}

func TestSplitWithPSKAndHostEndpoint(t *testing.T) {
	c, err := parseConfText(conf("[Interface]", "PrivateKey = "+kPriv, "Address = 10.8.0.3", "MTU = 1380",
		"[Peer]", "PublicKey = "+kPub, "PresharedKey = "+kPSK, "AllowedIPs = 10.8.0.0/24, 192.168.50.7, fd00::/64",
		"Endpoint = home.example.org:51820", "PersistentKeepalive = 0"), "home")
	if err != nil {
		t.Fatal(err)
	}
	if c.full() || !reflect.DeepEqual(c.Allowed, []string{"10.8.0.0/24", "192.168.50.7/32"}) {
		t.Fatalf("allowed %v", c.Allowed)
	}
	if c.PSK != kPSK || c.Address != "10.8.0.3/32" || c.MTU != 1380 || c.Keepalive != 0 || c.Endpoint != "home.example.org:51820" {
		t.Fatalf("got %+v", c)
	}
}

func TestNoAllowedIPsMeansFull(t *testing.T) {
	c, err := parseConfText(conf("PrivateKey="+kPriv, "Address=10.0.0.2/32", "[Peer]", "PublicKey="+kPub, "Endpoint=1.2.3.4:51820"), "x")
	if err != nil || !c.full() {
		t.Fatalf("%v %v", c, err)
	}
}

func TestRejects(t *testing.T) {
	base := []string{"[Interface]", "PrivateKey=" + kPriv, "Address=10.0.0.2/32", "[Peer]", "PublicKey=" + kPub, "Endpoint=1.2.3.4:51820"}
	with := func(extra ...string) string { return conf(append(append([]string{}, base...), extra...)...) }
	cases := map[string]string{
		"ipv6 only address": conf("PrivateKey="+kPriv, "Address=fd00::2/128", "[Peer]", "PublicKey="+kPub, "Endpoint=1.2.3.4:51820"),
		"ipv6 only allowed": with("AllowedIPs=::/0"),
		"ipv6 endpoint":     conf("PrivateKey="+kPriv, "Address=10.0.0.2/32", "[Peer]", "PublicKey="+kPub, "Endpoint=[2001:db8::1]:51820"),
		"two peers":         with("[Peer]", "PublicKey="+kPub, "Endpoint=5.6.7.8:51820"),
		"bad key":           conf("PrivateKey=notakey", "Address=10.0.0.2/32", "[Peer]", "PublicKey="+kPub, "Endpoint=1.2.3.4:51820"),
		"bad psk":           with("PresharedKey=abc"),
		"no port":           conf("PrivateKey="+kPriv, "Address=10.0.0.2/32", "[Peer]", "PublicKey="+kPub, "Endpoint=1.2.3.4"),
		"no endpoint":       conf("PrivateKey="+kPriv, "Address=10.0.0.2/32", "[Peer]", "PublicKey="+kPub),
		"bad allowed":       with("AllowedIPs=10.0.0.0/33"),
		"mtu":               with("MTU=9000"),
		"empty":             "",
	}
	for name, text := range cases {
		if _, err := parseConfText(text, "x"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProfileNames(t *testing.T) {
	for _, ok := range []string{"home", "Mullvad-IT_1", "a"} {
		if !profileName.MatchString(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "-x", ".hidden", "a b", "../x", "x;rm", strings.Repeat("a", 33)} {
		if profileName.MatchString(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
