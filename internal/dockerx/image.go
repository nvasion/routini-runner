package dockerx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/errdefs"
)

// EnsureImage makes ref available locally, pulling it without registry auth.
func (d *dockerClient) EnsureImage(ctx context.Context, ref, pull string) error {
	if err := validateRef(ref); err != nil {
		return err
	}
	policy, err := pullPolicy(pull)
	if err != nil {
		return err
	}
	if policy == PullMissing {
		_, _, err := d.api.ImageInspectWithRaw(ctx, ref)
		switch {
		case err == nil:
			return nil
		case errdefs.IsNotFound(err):
			// Absent locally: fall through and pull it.
		default:
			return fmt.Errorf("dockerx: inspect image %s: %w", ref, err)
		}
	}
	return d.pullImage(ctx, ref)
}

// pullPolicy normalises the wire value; an empty policy means PullMissing.
func pullPolicy(pull string) (string, error) {
	switch pull {
	case "", PullMissing:
		return PullMissing, nil
	case PullAlways:
		return PullAlways, nil
	default:
		return "", fmt.Errorf("dockerx: unknown pull policy %q (want %q or %q)", pull, PullMissing, PullAlways)
	}
}

// pullImage pulls ref anonymously and reports a failure reported inside the
// progress stream, which the Engine API sends with a 200 status.
func (d *dockerClient) pullImage(ctx context.Context, ref string) error {
	// PullOptions is left empty on purpose: this package never sends
	// registry credentials.
	body, err := d.api.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("dockerx: pull image %s: %w", ref, err)
	}
	defer body.Close()
	if err := drainPullProgress(body); err != nil {
		return fmt.Errorf("dockerx: pull image %s: %w", ref, err)
	}
	return nil
}

// pullProgress is the part of a docker pull progress message that reports a
// failure.
type pullProgress struct {
	Error       string `json:"error"`
	ErrorDetail struct {
		Message string `json:"message"`
	} `json:"errorDetail"`
}

// drainPullProgress reads the whole progress stream, which is what makes the
// pull run to completion, and returns the first error it reports.
func drainPullProgress(r io.Reader) error {
	dec := json.NewDecoder(r)
	var failure error
	for {
		var msg pullProgress
		switch err := dec.Decode(&msg); {
		case errors.Is(err, io.EOF):
			return failure
		case err != nil:
			if failure != nil {
				return failure
			}
			return fmt.Errorf("read progress stream: %w", err)
		}
		if failure != nil {
			continue
		}
		if m := msg.ErrorDetail.Message; m != "" {
			failure = errors.New(m)
		} else if msg.Error != "" {
			failure = errors.New(msg.Error)
		}
	}
}
