package landing

import "testing"

func TestAvailabilityConsecutiveThresholds(t *testing.T) {
	var a availability
	steps := []struct{ success, network, up bool }{
		{true, false, false}, {true, false, true},
		{false, true, true}, {false, true, true}, {false, true, false},
		{true, false, false}, {false, true, false},
		{true, false, false}, {true, false, true},
		{false, false, false}, // security failure is immediate
		{true, false, false}, {true, false, true},
		{false, true, true}, {true, false, true}, {false, true, true},
	}
	for i, step := range steps {
		if got := a.observe(step.success, step.network); got != step.up {
			t.Fatalf("step %d: %+v", i, a)
		}
	}
}
