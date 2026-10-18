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
	Landing landing.Plan `json:"landing"`
}

func NewDesired(plan landing.Plan) (Desired, error) {
	a, err := plan.Artifact()
	if err != nil {
		return Desired{}, err
	}
	plan.Sources = slices.Clone(plan.Sources)
	return Desired{DesiredArtifact: a, Landing: plan}, nil
}

func (d Desired) Validate() error {
	if err := d.DesiredArtifact.Validate(); err != nil {
		return err
	}
	expected, err := d.Landing.Artifact()
	if err != nil || expected.Revision != d.Revision || expected.ConfigSHA256 != d.ConfigSHA256 || !bytes.Equal(expected.Config, d.Config) {
		return errors.New("control: configuration and landing policy differ")
	}
	return nil
}

func (d Desired) clone() Desired {
	d.Config = bytes.Clone(d.Config)
	d.Landing.Sources = slices.Clone(d.Landing.Sources)
	return d
}
