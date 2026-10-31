package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/petauron/glivela/control"
)

func verifyRoute(ctx context.Context, path string, output io.Writer) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute route request path required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
		return errors.New("unsafe route request")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request control.RouteProbe
	var trailing any
	if decoder.Decode(&request) != nil || decoder.Decode(&trailing) != io.EOF || request.Validate() != nil {
		return errors.New("invalid route request")
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	result, checkErr := control.CheckRoute(bounded, request)
	if err := json.NewEncoder(output).Encode(result); err != nil {
		return err
	}
	return checkErr
}
