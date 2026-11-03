package control

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"

	glivela "github.com/petauron/glivela"
)

const hostBindingsFile = "host-bindings.json"

type hostBindingState struct {
	Version  int               `json:"version"`
	Bindings map[string]string `json:"bindings"`
}

func (v hostBindingState) validate() error {
	if v.Version != 1 || v.Bindings == nil || len(v.Bindings) > 10000 {
		return errors.New("control: invalid host bindings")
	}
	for node, agent := range v.Bindings {
		if !glivela.ValidIdentifier(node) || !glivela.ValidIdentifier(agent) {
			return errors.New("control: invalid host binding")
		}
	}
	return nil
}

func (s *Store) loadHostBindings() error {
	var state hostBindingState
	err := readControlState(filepath.Join(filepath.Dir(s.path), hostBindingsFile), &state)
	if errors.Is(err, os.ErrNotExist) {
		s.hostBindings = map[string]string{}
		return nil
	}
	if err != nil || state.validate() != nil {
		return errors.New("control: invalid host bindings")
	}
	s.hostBindings = state.Bindings
	return nil
}

// BindHost changes only the display association; it never alters runtime,
// credentials, subscription contents or the original imported name.
func (s *Store) BindHost(ctx context.Context, nodeID, expectedAgentID, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: host binding refused")
	if ctx.Err() != nil || !glivela.ValidIdentifier(nodeID) || agentID != "" && !glivela.ValidIdentifier(agentID) || s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return invalid
	}
	_, known := s.business.material.References.Nodes[nodeID]
	if !known {
		for _, node := range s.nodes {
			if node.ID == nodeID && !s.entryRetiredLocked(node.ID) && runtimeHostID(s.business.material, node) == "" {
				known = true
				break
			}
		}
	}
	if !known || s.hostBindings[nodeID] != expectedAgentID {
		return invalid
	}
	if s.hostBindings[nodeID] == agentID {
		return nil
	}
	path := filepath.Join(filepath.Dir(s.path), hostBindingsFile)
	var before hostBindingState
	readErr := readControlState(path, &before)
	if errors.Is(readErr, os.ErrNotExist) {
		if len(s.hostBindings) != 0 {
			return invalid
		}
	} else if readErr != nil || before.validate() != nil || !reflect.DeepEqual(before.Bindings, s.hostBindings) {
		return invalid
	}
	next := hostBindingState{Version: 1, Bindings: maps.Clone(s.hostBindings)}
	if agentID == "" {
		delete(next.Bindings, nodeID)
	} else {
		next.Bindings[nodeID] = agentID
	}
	err := writeControlState(path, next)
	var observed hostBindingState
	if readControlState(path, &observed) != nil || observed.validate() != nil || !reflect.DeepEqual(observed, next) {
		return errors.New("control: host binding write not confirmed")
	}
	s.hostBindings = observed.Bindings
	return err
}
