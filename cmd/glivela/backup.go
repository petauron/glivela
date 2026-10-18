package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"strings"
)

// This local preparation command has no service-control or authority-transfer
// step. The returned checkpoint is private recovery data, not a health receipt.
func backupLandingCommand(args []string, output io.Writer, backup func(string, string) (string, error)) error {
	flags := flag.NewFlagSet("backup-legacy-landing", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	node := flags.String("node-id", "", "existing node identity")
	directory := flags.String("directory", "", "existing private recovery directory")
	if err := flags.Parse(args); err != nil {
		return errors.New("invalid backup options")
	}
	if flags.NArg() != 0 || *node == "" || len(*node) > 128 || strings.ContainsAny(*node, "\x00\r\n") || !filepath.IsAbs(*directory) || filepath.Clean(*directory) != *directory || *directory == "/" {
		return errors.New("explicit node identity and private backup directory required")
	}
	checkpoint, err := backup(*directory, *node)
	if err != nil {
		return errors.New("legacy recovery checkpoint not verified")
	}
	return json.NewEncoder(output).Encode(struct {
		Status     string `json:"status"`
		Checkpoint string `json:"checkpoint"`
	}{Status: "backup-only", Checkpoint: checkpoint})
}
