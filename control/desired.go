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
	// Missing in pre-policy snapshots: validate their original configuration.
	EntryRenderVersion   uint8 `json:"entryRenderVersion,omitempty"`
	LandingRenderVersion uint8 `json:"landingRenderVersion,omitempty"`

	Landing      *landing.Plan     `json:"landing,omitempty"`
	Entry        *glivela.XrayPlan `json:"entry,omitempty"`
	EntryNetwork *EntryNetwork     `json:"entryNetwork,omitempty"`
}

func NewDesired(plan landing.Plan) (Desired, error) {
	version := landing.RenderVersion
	// Ordinary listener projections must remain consumable by unchanged nodes.
	if plan.IPv6OnlyAddress == "" {
		version = 2
	}
	return newLandingDesiredVersion(plan, version)
}

func newLandingDesiredVersion(plan landing.Plan, version uint8) (Desired, error) {
	if version >= 1 {
		plan.PublicSSH = nil
	}
	a, err := plan.ArtifactVersion(version)
	if err != nil {
		return Desired{}, err
	}
	plan.Sources = slices.Clone(plan.Sources)
	plan.ClientListeners = slices.Clone(plan.ClientListeners)
	return Desired{DesiredArtifact: a, LandingRenderVersion: version, Landing: &plan}, nil
}

// NewEntryDesired selects the current format for new enrollment or an explicit
// managed update after the node has a compatible program. Routine projections
// retain EntryRenderVersion through newEntryDesiredVersion.
func NewEntryDesired(plan glivela.XrayPlan, network EntryNetwork) (Desired, error) {
	return newEntryDesiredVersion(plan, network, glivela.XrayRenderVersion)
}

func newEntryDesiredVersion(plan glivela.XrayPlan, network EntryNetwork, version uint8) (Desired, error) {
	if version >= 2 {
		plan.PublicSSH = nil
	}
	if _, err := entryPlanIdentity(plan); err != nil {
		return Desired{}, err
	}
	artifact, err := glivela.BuildDesiredArtifactVersion(plan, version)
	if err != nil {
		return Desired{}, err
	}
	if err := network.validate(plan); err != nil {
		return Desired{}, err
	}
	return (Desired{DesiredArtifact: artifact, EntryRenderVersion: version, Entry: &plan, EntryNetwork: &network}).clone(), nil
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
		if d.EntryRenderVersion != 0 || d.LandingRenderVersion > landing.RenderVersion || d.LandingRenderVersion > 0 && d.Landing.PublicSSH != nil {
			return errors.New("control: invalid landing render policy")
		}
		expected, err = d.Landing.ArtifactVersion(d.LandingRenderVersion)
	} else {
		if d.LandingRenderVersion != 0 || d.EntryRenderVersion >= 2 && d.Entry.PublicSSH != nil {
			return errors.New("control: invalid entry render policy")
		}
		if _, err := entryPlanIdentity(*d.Entry); err != nil {
			return err
		}
		expected, err = glivela.BuildDesiredArtifactVersion(*d.Entry, d.EntryRenderVersion)
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
		plan.PublicSSH = plan.PublicSSH.Clone()
		plan.Sources = slices.Clone(plan.Sources)
		plan.ClientListeners = slices.Clone(plan.ClientListeners)
		d.Landing = &plan
	}
	if d.Entry != nil {
		plan := *d.Entry
		plan.PublicSSH = plan.PublicSSH.Clone()
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
