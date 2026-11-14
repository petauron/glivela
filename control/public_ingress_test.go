package control

import (
	"context"
	"encoding/json"
	glivela "github.com/petauron/glivela"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func publicIngressResolver(t *testing.T, dual *atomic.Bool) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
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
				if v.Type == dnsmessage.TypeAAAA {
					a.Answers = append(a.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: v.Name, Type: v.Type, Class: dnsmessage.ClassINET, TTL: 10}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88}}})
				}
				if v.Type == dnsmessage.TypeA && dual.Load() {
					a.Answers = append(a.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: v.Name, Type: v.Type, Class: dnsmessage.ClassINET, TTL: 10}, Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}})
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
	t.Cleanup(func() { net.DefaultResolver = previous })
}
func publicIngressFixture(t *testing.T) (*Store, glivela.ImportEndpoint, map[string]Node) {
	t.Helper()
	s, _, _, _ := subscriptionFixture(t, false)
	m := s.business.material
	m.Endpoints = append([]glivela.ImportEndpoint(nil), m.Endpoints...)
	e := &m.Endpoints[0]
	e.Reality.ListenAddress = "2001:4860:4860::8888"
	e.Reality.ListenPort = 24443
	e.Reality.AdvertisePort = 24443
	e.Reality.Target = "site.example.test:24483"
	e.Reality.ServerNames = []string{"site.example.test"}
	e.TargetIP = "127.0.0.1"
	nodes := s.copy()
	for cert, node := range nodes {
		if node.ID == e.Reality.EntryID {
			plan := *node.Desired.clone().Entry
			plan.RealityEndpoints[0] = pinnedImportedReality(*e)
			plan.Revision++
			var err error
			node.Desired, err = newEntryDesiredVersion(plan, *node.Desired.EntryNetwork, node.Desired.EntryRenderVersion)
			if err != nil {
				t.Fatal(err)
			}
			node.Receipt = nil
			nodes[cert] = node
		}
	}
	if err := s.saveOwnedBusinessLocked(m); err != nil {
		t.Fatal(err)
	}
	if err := s.commit(nodes); err != nil {
		t.Fatal(err)
	}
	return s, *e, nodes
}

func TestPublicIngress443PreservesBusinessAndRecoversProjection(t *testing.T) {
	var dual atomic.Bool
	dual.Store(true)
	publicIngressResolver(t, &dual)
	s, endpoint, nodes := publicIngressFixture(t)
	e := &endpoint
	before := s.business.material
	resource := ManagedIngressResource{ID: "resource-example", Hostname: e.Reality.AdvertiseHost, Address: e.Reality.ListenAddress, Type: "AAAA", SecondaryAddress: "1.1.1.1", Revision: 2, AppliedRevision: 2, Status: "ready"}
	raw, _ := json.Marshal(resource)
	input := PublicIngressChange{EntryID: e.Reality.EntryID, Action: "apply", ExpectedRevision: e.DesiredRevision, Resource: raw}
	stale := input
	stale.ExpectedRevision++
	if _, err := s.ChangePublicIngress(context.Background(), stale); err == nil {
		t.Fatal("stale revision accepted")
	}
	view, err := s.ChangePublicIngress(context.Background(), input)
	if err != nil || view.Port != 443 || view.IPv4ListenAddress != "1.1.1.1" {
		t.Fatal("apply", view, err)
	}
	again, err := s.ChangePublicIngress(context.Background(), input)
	if err != nil || view != again {
		t.Fatal("lost response retry", err)
	}
	after := s.business.material
	if !reflect.DeepEqual(before.Plan, after.Plan) || !reflect.DeepEqual(before.ProtocolSecrets, after.ProtocolSecrets) || !reflect.DeepEqual(before.SubscriptionTokens, after.SubscriptionTokens) || !reflect.DeepEqual(before.TrafficCounters, after.TrafficCounters) || !reflect.DeepEqual(before.ResetSchedules, after.ResetSchedules) {
		t.Fatal("public listener changed business identities or usage")
	}
	original, current := before.Endpoints[0].Reality, after.Endpoints[0].Reality
	original.ListenPort = 443
	original.AdvertisePort = 443
	original.IPv4ListenAddress = "1.1.1.1"
	if !reflect.DeepEqual(original, current) {
		t.Fatal("listener change altered SNI or keys")
	}
	// Reconstruct an interrupted projection from the authenticated previous tuple.
	recovered, changed, err := projectBusinessEntries(nodes, after, time.Now())
	if err != nil || !changed {
		t.Fatal("projection recovery", err)
	}
	if err = s.commit(recovered); err != nil {
		t.Fatal(err)
	}
	// DNS is explicitly restored before returning to the saved single-stack port.
	dual.Store(false)
	resource.SecondaryAddress = ""
	resource.Revision++
	resource.AppliedRevision = resource.Revision
	raw, _ = json.Marshal(resource)
	reverted, err := s.ChangePublicIngress(context.Background(), PublicIngressChange{EntryID: input.EntryID, Action: "revert", ExpectedRevision: view.Revision, Resource: raw})
	if err != nil || reverted.Port != 24443 || reverted.IPv4ListenAddress != "" {
		t.Fatal("explicit recovery", reverted, err)
	}
}
