package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/petauron/glivela/control"
)

func retireEntryCommand(parent context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("retire-entry", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "private entry node journal directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" {
		return errors.New("entry retirement requires its private node directory")
	}
	distribution, err := runningDistribution()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	if err := control.RetireEntry(ctx, *directory, distribution); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
	}{Status: "entry-retired-stop-confirmed"})
}

// Application-owned initialization is explicit and atomic. The host's normal
// upgrade never rewrites these post-install settings.
func savePrivateConfiguration(path string, original []byte, cfg configuration) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private regular application bootstrap required")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("application bootstrap ownership unavailable")
	}
	replacement, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, original) {
		return errors.New("application bootstrap changed during maintenance; existing state retained")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".glivela-bootstrap-")
	if err != nil {
		return err
	}
	defer file.Close()
	defer os.Remove(file.Name())
	created, err := file.Stat()
	if err != nil {
		return err
	}
	createdOwner, ok := created.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("replacement bootstrap ownership unavailable")
	}
	if createdOwner.Uid != owner.Uid || createdOwner.Gid != owner.Gid {
		if err := file.Chown(int(owner.Uid), int(owner.Gid)); err != nil {
			return err
		}
	}
	if _, err := file.Write(replacement); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	latest, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, latest) {
		return errors.New("application bootstrap replaced during maintenance; existing state retained")
	}
	current, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(current, original) {
		return errors.New("application bootstrap changed during maintenance; existing state retained")
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	return nil
}

func backupEntryCommand(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("backup-legacy-entry", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "private root-owned backup directory")
	container := flags.String("container", "", "exact legacy container ID")
	application := flags.String("application", "", "original application identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || *container == "" || *application == "" {
		return errors.New("entry backup requires directory, container and application")
	}
	checkpoint, err := control.BackupLegacyEntry(ctx, *directory, *container, *application)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Checkpoint string `json:"checkpoint"`
	}{Checkpoint: checkpoint})
}
