package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// wgConfToUAPI converts a wg(8) configuration file (the format `wg setconf`
// reads: [Interface] PrivateKey/ListenPort, [Peer] PublicKey/PresharedKey/
// AllowedIPs/Endpoint/PersistentKeepalive) into the UAPI text device.IpcSet
// takes. wg-quick's extra Interface keys (Address, DNS, MTU, Table, Post*)
// are ignored so the same file can serve wg-quick and wgpio; the gateway's
// addresses come from its flags. It returns the listen port too, since the
// gateway must know it before the device is up.
func wgConfToUAPI(r io.Reader) (uapi string, listenPort uint16, err error) {
	var b strings.Builder
	section := ""
	line := 0
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "[") {
			section = strings.ToLower(strings.Trim(s, "[]"))
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return "", 0, fmt.Errorf("line %d: expected key = value", line)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch section {
		case "interface":
			switch k {
			case "privatekey":
				h, err := keyHex(v)
				if err != nil {
					return "", 0, fmt.Errorf("line %d: PrivateKey: %w", line, err)
				}
				fmt.Fprintf(&b, "private_key=%s\n", h)
			case "listenport":
				p, err := strconv.ParseUint(v, 10, 16)
				if err != nil {
					return "", 0, fmt.Errorf("line %d: ListenPort: %w", line, err)
				}
				listenPort = uint16(p)
			case "address", "dns", "mtu", "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark":
				// wg-quick's business, not the device's.
			default:
				return "", 0, fmt.Errorf("line %d: unknown [Interface] key %q", line, k)
			}
		case "peer":
			switch k {
			case "publickey":
				h, err := keyHex(v)
				if err != nil {
					return "", 0, fmt.Errorf("line %d: PublicKey: %w", line, err)
				}
				fmt.Fprintf(&b, "public_key=%s\n", h)
			case "presharedkey":
				h, err := keyHex(v)
				if err != nil {
					return "", 0, fmt.Errorf("line %d: PresharedKey: %w", line, err)
				}
				fmt.Fprintf(&b, "preshared_key=%s\n", h)
			case "allowedips":
				for _, p := range strings.Split(v, ",") {
					p = strings.TrimSpace(p)
					if _, err := netip.ParsePrefix(p); err != nil {
						if a, err2 := netip.ParseAddr(p); err2 == nil {
							p = netip.PrefixFrom(a, a.BitLen()).String()
						} else {
							return "", 0, fmt.Errorf("line %d: AllowedIPs %q: %w", line, p, err)
						}
					}
					fmt.Fprintf(&b, "allowed_ip=%s\n", p)
				}
			case "endpoint":
				fmt.Fprintf(&b, "endpoint=%s\n", v)
			case "persistentkeepalive":
				if _, err := strconv.ParseUint(v, 10, 16); err != nil {
					return "", 0, fmt.Errorf("line %d: PersistentKeepalive: %w", line, err)
				}
				fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", v)
			default:
				return "", 0, fmt.Errorf("line %d: unknown [Peer] key %q", line, k)
			}
		default:
			return "", 0, fmt.Errorf("line %d: key outside a section", line)
		}
	}
	if err := sc.Err(); err != nil {
		return "", 0, err
	}
	if !strings.Contains(b.String(), "private_key=") {
		return "", 0, fmt.Errorf("no PrivateKey in [Interface]")
	}
	return b.String(), listenPort, nil
}

// keyHex turns a base64 WireGuard key into the hex UAPI wants.
func keyHex(b64 string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(k) != 32 {
		return "", fmt.Errorf("not a base64 32-byte key")
	}
	return hex.EncodeToString(k), nil
}
