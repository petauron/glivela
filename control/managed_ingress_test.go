package control

import (
	"context"
	"encoding/json"
	"net"
	"reflect"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestManagedIngressRetainsIdentityAndRejectsUnreadyResources(t *testing.T) {
	// Resolver traffic stays on loopback; there is no public DNS or proxy traffic.
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 4096)
		for {
			n, peer, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(b[:n]) != nil {
				continue
			}
			a := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
			for _, v := range q.Questions {
				if v.Type == dnsmessage.TypeA {
					a.Answers = append(a.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: v.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 10}, Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}})
				}
			}
			raw, _ := a.Pack()
			_, _ = udp.WriteTo(raw, peer)
		}
	}()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", udp.LocalAddr().String())
	}}
	defer func() { net.DefaultResolver = previous }()
	s, _, _, _ := subscriptionFixture(t, true)
	before := s.business.material
	endpoint := before.Endpoints[0]
	resource := ManagedIngressResource{ID: "resource-example", Hostname: "random.example.test", Address: "1.1.1.1", Type: "A", Revision: 1, AppliedRevision: 1, Status: "ready"}
	input := AdvertiseHostChange{EntryID: endpoint.Reality.EntryID, Action: "apply", ExpectedRevision: endpoint.DesiredRevision}
	resource.Status = "pending"
	input.Resource, _ = json.Marshal(resource)
	if _, err := s.ChangeAdvertiseHost(context.Background(), input); err == nil {
		t.Fatal("unready resource accepted")
	}
	if !reflect.DeepEqual(before, s.business.material) {
		t.Fatal("refused resource changed business")
	}
	resource.Status = "ready"
	input.Resource, _ = json.Marshal(resource)
	view, err := s.ChangeAdvertiseHost(context.Background(), input)
	if err != nil || view.Host != resource.Hostname {
		t.Fatalf("apply: %+v %v", view, err)
	}
	again, err := s.ChangeAdvertiseHost(context.Background(), input)
	if err != nil || view != again {
		t.Fatalf("retry: %+v %v", again, err)
	}
	after := s.business.material
	if !reflect.DeepEqual(before.Plan, after.Plan) || !reflect.DeepEqual(before.ProtocolSecrets, after.ProtocolSecrets) || !reflect.DeepEqual(before.SubscriptionTokens, after.SubscriptionTokens) || !reflect.DeepEqual(before.TrafficCounters, after.TrafficCounters) || !reflect.DeepEqual(before.ResetSchedules, after.ResetSchedules) {
		t.Fatal("domain change altered account, credentials or ledger")
	}
	old, new := endpoint.Reality, after.Endpoints[0].Reality
	old.AdvertiseHost = new.AdvertiseHost
	if !reflect.DeepEqual(old, new) {
		t.Fatal("domain change altered SNI, listener or protocol identity")
	}
	resource.Hostname = new.ServerNames[0]
	input.ExpectedRevision = view.Revision
	input.Resource, _ = json.Marshal(resource)
	if _, err := s.ChangeAdvertiseHost(context.Background(), input); err == nil {
		t.Fatal("SNI reused as ingress")
	}
}
