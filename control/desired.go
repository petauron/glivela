package control

import (
	"bytes"
	"errors"
	"slices"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// Desired binds the Xray configuration to the policy used for kernel filtering.
// The direct node protocol never accepts an arbitrary standalone core config.
// Vastora neither transports nor interprets this application-owned state.
type Desired struct {
	glivela.DesiredArtifact
	Landing      *landing.Plan     `json:"landing,omitempty"`
	Entry        *glivela.XrayPlan `json:"entry,omitempty"`
	EntryNetwork *EntryNetwork     `json:"entryNetwork,omitempty"`
}

func NewDesired(plan landing.Plan) (Desired, error) {
	a, err := plan.Artifact()
	if err != nil {
		return Desired{}, err
	}
	plan.Sources = slices.Clone(plan.Sources)
	return Desired{DesiredArtifact: a, Landing: &plan}, nil
}

func NewEntryDesired(plan glivela.XrayPlan, network EntryNetwork) (Desired, error) {
	if _, err := entryPlanIdentity(plan); err != nil {
		return Desired{}, err
	}
	artifact, err := glivela.BuildDesiredArtifact(plan)
	if err != nil {
		return Desired{}, err
	}
	if err := network.validate(plan); err != nil {
		return Desired{}, err
	}
	return (Desired{DesiredArtifact: artifact, Entry: &plan, EntryNetwork: &network}).clone(), nil
}

func (d Desired) Validate() error {
	if err := d.DesiredArtifact.Validate(); err != nil {
		return err
	}
	if (d.Landing == nil) == (d.Entry == nil) {
		return errors.New("control: exactly one entry or landing plan required")
	}
	if (d.Entry == nil) != (d.EntryNetwork == nil) {
		return errors.New("control: exact entry network policy required")
	}
	var expected glivela.DesiredArtifact
	var err error
	if d.Landing != nil {
		expected, err = d.Landing.Artifact()
	} else {
		if _, err := entryPlanIdentity(*d.Entry); err != nil {
			return err
		}
		expected, err = glivela.BuildDesiredArtifact(*d.Entry)
		if err == nil {
			err = d.EntryNetwork.validate(*d.Entry)
		}
	}
	if err != nil || expected.Revision != d.Revision || expected.ConfigSHA256 != d.ConfigSHA256 || !bytes.Equal(expected.Config, d.Config) {
		return errors.New("control: configuration and owned proxy plan differ")
	}
	return nil
}

func (d Desired) clone() Desired {
	d.Config = bytes.Clone(d.Config)
	if d.Landing != nil {
		plan := *d.Landing
		plan.Sources = slices.Clone(plan.Sources)
		d.Landing = &plan
	}
	if d.Entry != nil {
		plan := *d.Entry
		plan.RealityEndpoints = slices.Clone(plan.RealityEndpoints)
		for i := range plan.RealityEndpoints {
			plan.RealityEndpoints[i].ServerNames = slices.Clone(plan.RealityEndpoints[i].ServerNames)
			plan.RealityEndpoints[i].ShortIDs = slices.Clone(plan.RealityEndpoints[i].ShortIDs)
		}
		plan.HysteriaEndpoints = slices.Clone(plan.HysteriaEndpoints)
		plan.Credentials = slices.Clone(plan.Credentials)
		plan.Grants = slices.Clone(plan.Grants)
		plan.Peers = slices.Clone(plan.Peers)
		d.Entry = &plan
	}
	if d.EntryNetwork != nil {
		network := d.EntryNetwork.clone()
		d.EntryNetwork = &network
	}
	return d
}
