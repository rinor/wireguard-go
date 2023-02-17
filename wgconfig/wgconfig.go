//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package wgconfig

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

type ParseError struct {
	why      string
	offender string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s: %q", e.why, e.offender)
}

const KeyLen = 32

type Key [KeyLen]byte

func (k *Key) IsZero() bool {
	var zeros Key
	return subtle.ConstantTimeCompare(zeros[:], k[:]) == 1
}

func (k *Key) Hex() string {
	return hex.EncodeToString(k[:])
}

type Endpoint struct {
	Host string
	Port uint16
}

func (e *Endpoint) string() string {
	if strings.IndexByte(e.Host, ':') != -1 {
		return fmt.Sprintf("[%s]:%d", e.Host, e.Port)
	}
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

type Config struct {
	Interface DeviceConfig
	Peers     []PeerConfig
}

func (c *Config) maybeAddPeer(p *PeerConfig) {
	if p != nil {
		c.Peers = append(c.Peers, *p)
	}
}

type DeviceConfig struct {
	PrivateKey   *Key
	ListenPort   *uint16
	FirewallMark *int
	ReplacePeers bool
}

type PeerConfig struct {
	PublicKey           Key
	Remove              bool
	UpdateOnly          bool
	PresharedKey        *Key
	Endpoint            *Endpoint
	PersistentKeepalive *uint16
	ReplaceAllowedIPs   bool
	AllowedIPs          []netip.Prefix
}

func parseKeyBase64(s string) (*Key, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, &ParseError{fmt.Sprintf("Invalid key: %v", err), s}
	}
	if len(k) != KeyLen {
		return nil, &ParseError{"Keys must decode to exactly 32 bytes", s}
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}

func parsePort(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{"Invalid port", s}
	}
	return uint16(m), nil
}

func parseIPCidr(s string) (netip.Prefix, error) {
	ipcidr, err := netip.ParsePrefix(s)
	if err == nil {
		return ipcidr, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, &ParseError{"Invalid IP address", s}
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func parsePersistentKeepalive(s string) (uint16, error) {
	if s == "off" {
		return 0, nil
	}
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{"Invalid persistent keepalive", s}
	}
	return uint16(m), nil
}

func parseEndpoint(s string) (*Endpoint, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return nil, &ParseError{"Missing port from endpoint", s}
	}
	host, portStr := s[:i], s[i+1:]
	if len(host) < 1 {
		return nil, &ParseError{"Invalid endpoint host", host}
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}
	hostColon := strings.IndexByte(host, ':')
	if host[0] == '[' || host[len(host)-1] == ']' || hostColon > 0 {
		err := &ParseError{"Brackets must contain an IPv6 address", host}
		if len(host) > 3 && host[0] == '[' && host[len(host)-1] == ']' && hostColon > 0 {
			end := len(host) - 1
			if i := strings.LastIndexByte(host, '%'); i > 1 {
				end = i
			}
			maybeV6, err2 := netip.ParseAddr(host[1:end])
			if err2 != nil || !maybeV6.Is6() {
				return nil, err
			}
		} else {
			return nil, err
		}
		host = host[1 : len(host)-1]
	}
	return &Endpoint{host, port}, nil
}

func splitList(s string) ([]string, error) {
	var out []string
	for _, split := range strings.Split(s, ",") {
		trim := strings.TrimSpace(split)
		if len(trim) == 0 {
			return nil, &ParseError{"Two commas in a row", s}
		}
		out = append(out, trim)
	}
	return out, nil
}

func Parse(r io.Reader) (*Config, error) {
	const (
		inInterfaceSection = iota
		inPeerSection
		notInASection
	)
	var (
		parserState   = notInASection
		sawPrivateKey = false

		cfg  Config
		peer *PeerConfig

		scanner = bufio.NewScanner(r)
	)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		lineLower := strings.ToLower(line)
		if lineLower == "[interface]" {
			cfg.maybeAddPeer(peer)
			parserState = inInterfaceSection
			continue
		}
		if lineLower == "[peer]" {
			cfg.maybeAddPeer(peer)
			peer = &PeerConfig{}
			parserState = inPeerSection
			continue
		}
		if parserState == notInASection {
			return nil, &ParseError{"Line must occur in a section", line}
		}
		equals := strings.IndexByte(line, '=')
		if equals < 0 {
			return nil, &ParseError{"Config key is missing an equals separator", line}
		}
		key, val := strings.TrimSpace(lineLower[:equals]), strings.TrimSpace(line[equals+1:])
		if len(val) == 0 {
			return nil, &ParseError{"Key must have a value", line}
		}
		if parserState == inInterfaceSection {
			switch key {
			case "privatekey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				cfg.Interface.PrivateKey = k
				sawPrivateKey = true
			case "listenport":
				p, err := parsePort(val)
				if err != nil {
					return nil, err
				}
				cfg.Interface.ListenPort = &p
			case "address", "mtu", "dns", "preup", "postup", "predown", "postdown", "table":
				// nothing to do in nanos, just skip them
			default:
				return nil, &ParseError{"Invalid key for [Interface] section", key}
			}
		} else if parserState == inPeerSection {
			switch key {
			case "publickey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				peer.PublicKey = *k
			case "presharedkey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				peer.PresharedKey = k
			case "allowedips":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := parseIPCidr(address)
					if err != nil {
						return nil, err
					}
					peer.AllowedIPs = append(peer.AllowedIPs, a)
				}
			case "persistentkeepalive":
				p, err := parsePersistentKeepalive(val)
				if err != nil {
					return nil, err
				}
				peer.PersistentKeepalive = &p
			case "endpoint":
				e, err := parseEndpoint(val)
				if err != nil {
					return nil, err
				}
				peer.Endpoint = e
			default:
				return nil, &ParseError{"Invalid key for [Peer] section", key}
			}
		}
	}
	cfg.maybeAddPeer(peer)

	if !sawPrivateKey {
		return nil, &ParseError{"An interface must have a private key", "[none specified]"}
	}
	for _, p := range cfg.Peers {
		if p.PublicKey.IsZero() {
			return nil, &ParseError{"All peers must have public keys", "[none specified]"}
		}
	}

	return &cfg, nil
}

func Write(w io.Writer, cfg *Config) {
	if cfg.Interface.PrivateKey != nil {
		fmt.Fprintf(w, "private_key=%s\n", cfg.Interface.PrivateKey.Hex())
	}
	if cfg.Interface.ListenPort != nil {
		fmt.Fprintf(w, "listen_port=%d\n", *cfg.Interface.ListenPort)
	}
	if cfg.Interface.FirewallMark != nil {
		fmt.Fprintf(w, "fwmark=%d\n", *cfg.Interface.FirewallMark)
	}
	if cfg.Interface.ReplacePeers {
		fmt.Fprintln(w, "replace_peers=true")
	}
	for _, p := range cfg.Peers {
		fmt.Fprintf(w, "public_key=%s\n", p.PublicKey.Hex())
		if p.Remove {
			fmt.Fprintln(w, "remove=true")
		}
		if p.UpdateOnly {
			fmt.Fprintln(w, "update_only=true")
		}
		if p.PresharedKey != nil {
			fmt.Fprintf(w, "preshared_key=%s\n", p.PresharedKey.Hex())
		}
		if p.Endpoint != nil {
			fmt.Fprintf(w, "endpoint=%s\n", p.Endpoint.string())
		}
		if p.PersistentKeepalive != nil {
			fmt.Fprintf(w, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
		if p.ReplaceAllowedIPs {
			fmt.Fprintln(w, "replace_allowed_ips=true")
		}
		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(w, "allowed_ip=%s\n", ip.String())
		}
	}
	fmt.Fprint(w, "\n")
}
