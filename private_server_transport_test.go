package glivela

import "testing"

func TestPrivateServerTransportRequiresBoundExactLink(t *testing.T) {
	link := PrivateClientLink{Source: "10.20.0.3", Address: "10.20.0.2", SourceInterface: "ens8", Interface: "ens8"}
	base := PrivateTransport{Protocol: "ss2022", Key: "MDEyMzQ1Njc4OWFiY2RlZg==", PublicAddress: link.Address, Port: 24000, ClientListenerID: "existing-client", PrivateLink: &link}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"unbound", "missing-link", "other-target", "wildcard-source", "management-target"} {
		p := base
		l := link
		p.PrivateLink = &l
		switch fault {
		case "unbound":
			p.ClientListenerID = ""
		case "missing-link":
			p.PrivateLink = nil
		case "other-target":
			p.PublicAddress = "10.20.0.4"
		case "wildcard-source":
			l.Source = "0.0.0.0"
		case "management-target":
			p.PublicAddress = "100.64.0.2"
			l.Address = p.PublicAddress
		}
		if p.Validate() == nil {
			t.Fatal("accepted", fault)
		}
	}
}
