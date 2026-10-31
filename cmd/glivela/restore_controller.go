package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/petauron/glivela/control"
)

func restoreControllerCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("restore-controller-backup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	source := flags.String("backup", "", "private Glivela controller snapshot")
	key := flags.String("storage-key", "", "retained independent business key file")
	destination := flags.String("destination", "", "new private restore directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *source == "" || *key == "" || *destination == "" {
		return errors.New("controller backup, retained key and new restore directory required")
	}
	if err := control.RestoreControllerBackup(*source, *key, *destination); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
	}{"restored-to-new-directory-not-activated"})
}
