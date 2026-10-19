//go:build !linux

package control

import "errors"

func verifyEntryProcess(EntryContainer, entryContainerState, Desired) error {
	return errors.New("control: entry process acceptance requires Linux")
}
