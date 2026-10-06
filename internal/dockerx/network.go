package dockerx

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/errdefs"
)

// EnsureNetwork creates an internal bridge network called name, labelled with
// labels, unless it already exists. Losing the race to another creator (the
// daemon answers 409) counts as success.
func (d *dockerClient) EnsureNetwork(ctx context.Context, name string, labels map[string]string) error {
	if err := validateName("network name", name); err != nil {
		return err
	}
	if err := validateLabels(labels); err != nil {
		return err
	}
	_, err := d.api.NetworkInspect(ctx, name, network.InspectOptions{})
	switch {
	case err == nil:
		return nil
	case errdefs.IsNotFound(err):
		// Absent: create it below.
	default:
		return fmt.Errorf("dockerx: inspect network %s: %w", name, err)
	}

	_, err = d.api.NetworkCreate(ctx, name, network.CreateOptions{
		Driver:   "bridge",
		Internal: true,
		Labels:   copyLabels(labels),
	})
	if err != nil && !isAlreadyThere(err) {
		return fmt.Errorf("dockerx: create network %s: %w", name, err)
	}
	return nil
}

// ConnectNetwork attaches container to network under alias. An alias is only
// requested when one is given.
func (d *dockerClient) ConnectNetwork(ctx context.Context, networkName, containerName, alias string) error {
	if err := validateName("network name", networkName); err != nil {
		return err
	}
	if err := validateName("container name", containerName); err != nil {
		return err
	}
	cfg := &network.EndpointSettings{}
	if alias != "" {
		if err := validateName("network alias", alias); err != nil {
			return err
		}
		cfg.Aliases = []string{alias}
	}
	err := d.api.NetworkConnect(ctx, networkName, containerName, cfg)
	// A 403 is how some daemon versions report an endpoint that is already
	// attached, so it is as good as success here.
	if err != nil && !isAlreadyThere(err) && !errdefs.IsForbidden(err) {
		return fmt.Errorf("dockerx: connect container %s to network %s: %w", containerName, networkName, err)
	}
	return nil
}

// isAlreadyThere reports whether err means the object the caller wanted to
// create already exists: a 409 Conflict, or the daemon's "already exists"
// message on versions that answer with a different status.
func isAlreadyThere(err error) bool {
	if err == nil {
		return false
	}
	return errdefs.IsConflict(err) || strings.Contains(strings.ToLower(err.Error()), "already exists")
}
