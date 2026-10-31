//go:build !linux

package control

import (
	"context"
	"errors"
)

func BackupLegacyEntry(context.Context, string, string, string) (string, error) {
	return "", errors.New("control: entry handover requires Linux")
}

func AdoptLegacyEntry(context.Context, string, EntryContainer, string, string, Desired) (EntryContainer, error) {
	return EntryContainer{}, errors.New("control: entry handover requires Linux")
}

func adoptLegacyEntry(context.Context, string, EntryContainer, string, string, Desired, bool) (EntryContainer, error) {
	return EntryContainer{}, errors.New("control: entry handover requires Linux")
}
