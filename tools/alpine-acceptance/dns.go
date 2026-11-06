package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Fixture-only split DNS keeps REALITY and inner HTTPS traffic inside the
// guest even when Xray uses its explicit resolver rather than /etc/hosts.
// Non-fixture names retain the guest's original resolver for build downloads.
func serveDNS(listen string) error {
	raw, err := os.ReadFile(root + "/dns-upstream")
	if err != nil {
		return err
	}
	upstream := strings.TrimSpace(string(raw))
	if net.ParseIP(upstream) == nil || upstream == "127.0.0.1" {
		return errors.New("original fixture DNS required")
	}
	socket, err := net.ListenPacket("udp4", listen)
	if err != nil {
		return err
	}
	defer socket.Close()
	permits := make(chan struct{}, 8)
	for {
		packet := make([]byte, 4096)
		n, peer, err := socket.ReadFrom(packet)
		if err != nil {
			return err
		}
		select {
		case permits <- struct{}{}:
		default:
			continue
		}
		go func(packet []byte, peer net.Addr) {
			defer func() { <-permits }()
			var query dnsmessage.Message
			if query.Unpack(packet) != nil || len(query.Questions) != 1 || query.Response {
				return
			}
			q := query.Questions[0]
			name := strings.ToLower(q.Name.String())
			if name == "www.example.com." || name == "www.cloudflare.com." || name == "entry.example.test." {
				answer := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true}, Questions: query.Questions}
				if q.Type == dnsmessage.TypeA {
					ip := [4]byte{93, 184, 216, 34}
					if name == "entry.example.test." {
						ip = [4]byte{100, 64, 0, 3}
					}
					answer.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: ip}}}
				}
				data, e := answer.Pack()
				if e == nil {
					socket.WriteTo(data, peer)
				}
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, e := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(upstream, "53"))
			if e != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = conn.Write(packet); e != nil {
				return
			}
			response := make([]byte, 4096)
			n, e := conn.Read(response)
			if e == nil {
				socket.WriteTo(response[:n], peer)
			}
		}(packet[:n], peer)
	}
}
