package dockerx

import (
	"context"
	"errors"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/errdefs"
)

// EnsureVolume creates the named volume, labelled with labels, unless it
// already exists. Losing the race to another creator (the daemon answers
// 409) counts as success.
func (d *dockerClient) EnsureVolume(ctx context.Context, name string, labels map[string]string) error {
	if err := validatePattern("volume name", name, envNameRe); err != nil {
		return err
	}
	if err := validateLabels(labels); err != nil {
		return err
	}
	_, err := d.api.VolumeInspect(ctx, name)
	switch {
	case err == nil:
		return nil
	case errdefs.IsNotFound(err):
		// Absent: create it below.
	default:
		return fmt.Errorf("dockerx: inspect volume %s: %w", name, err)
	}

	_, err = d.api.VolumeCreate(ctx, volume.CreateOptions{Name: name, Labels: copyLabels(labels)})
	if err != nil && !isAlreadyThere(err) {
		return fmt.Errorf("dockerx: create volume %s: %w", name, err)
	}
	return nil
}

// RemoveVolume removes the named volume. A missing volume is not an error,
// but a volume that was not created by this package (it lacks
// LabelManaged=true) is refused: callers must not be able to delete
// arbitrary host volumes just by guessing a name.
func (d *dockerClient) RemoveVolume(ctx context.Context, name string) error {
	if err := validatePattern("volume name", name, envNameRe); err != nil {
		return err
	}
	v, err := d.api.VolumeInspect(ctx, name)
	switch {
	case errdefs.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("dockerx: inspect volume %s: %w", name, err)
	}
	if v.Labels[LabelManaged] != "true" {
		return fmt.Errorf("dockerx: %s is not a Routini volume", name)
	}
	if err := d.api.VolumeRemove(ctx, name, true); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("dockerx: remove volume %s: %w", name, err)
	}
	return nil
}

// InspectVolume reports what is known about a volume. A missing volume is
// not an error: the zero VolumeInfo (Exists false) is returned.
func (d *dockerClient) InspectVolume(ctx context.Context, name string) (VolumeInfo, error) {
	if err := validatePattern("volume name", name, envNameRe); err != nil {
		return VolumeInfo{}, err
	}
	v, err := d.api.VolumeInspect(ctx, name)
	switch {
	case errdefs.IsNotFound(err):
		return VolumeInfo{}, nil
	case err != nil:
		return VolumeInfo{}, fmt.Errorf("dockerx: inspect volume %s: %w", name, err)
	}
	return VolumeInfo{Exists: true, Labels: v.Labels}, nil
}

// StartEnvContainer creates and starts one environment container, returning
// its id. If the start fails, the container created for it is removed so no
// half-created environment is left behind.
func (d *dockerClient) StartEnvContainer(ctx context.Context, spec EnvSpec) (string, error) {
	if err := spec.validate(); err != nil {
		return "", err
	}
	cfg, host := envContainerConfig(spec)
	created, err := d.api.ContainerCreate(ctx, cfg, host, nil, nil, spec.Name)
	if err != nil {
		return "", fmt.Errorf("dockerx: create container %s: %w", spec.Name, err)
	}
	if err := d.api.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		startErr := fmt.Errorf("dockerx: start container %s: %w", spec.Name, err)
		if rmErr := d.removeContainer(created.ID); rmErr != nil {
			return "", errors.Join(startErr, fmt.Errorf("dockerx: remove container %s: %w", spec.Name, rmErr))
		}
		return "", startErr
	}
	return created.ID, nil
}

// InspectEnv reports what is known about an environment container. A
// missing container is not an error: the zero EnvInfo (Exists false) is
// returned.
func (d *dockerClient) InspectEnv(ctx context.Context, id string) (EnvInfo, error) {
	if err := validateName("container id", id); err != nil {
		return EnvInfo{}, err
	}
	c, err := d.api.ContainerInspect(ctx, id)
	switch {
	case errdefs.IsNotFound(err):
		return EnvInfo{}, nil
	case err != nil:
		return EnvInfo{}, fmt.Errorf("dockerx: inspect container %s: %w", shortID(id), err)
	}
	info := EnvInfo{Exists: true}
	if c.State != nil {
		info.Running = c.State.Running
	}
	if c.Config != nil {
		info.Managed = isManagedEnv(c.Config.Labels)
		info.EnvID = c.Config.Labels[LabelEnvironment]
	}
	return info, nil
}

// RemoveEnvContainer force-removes an environment container. A missing
// container is not an error, but one that is not a managed environment
// container is refused, for the same reason RemoveVolume refuses an
// unmanaged volume.
func (d *dockerClient) RemoveEnvContainer(ctx context.Context, id string) error {
	if err := validateName("container id", id); err != nil {
		return err
	}
	c, err := d.api.ContainerInspect(ctx, id)
	switch {
	case errdefs.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("dockerx: inspect container %s: %w", shortID(id), err)
	}
	if c.Config == nil || !isManagedEnv(c.Config.Labels) {
		return fmt.Errorf("dockerx: %s is not a Routini environment container", shortID(id))
	}
	if err := d.api.ContainerRemove(ctx, id, container.RemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("dockerx: remove container %s: %w", shortID(id), err)
	}
	return nil
}

// CountEnvContainers reports how many running containers carry both
// LabelManaged=true and LabelEnvironment.
func (d *dockerClient) CountEnvContainers(ctx context.Context) (int, error) {
	args := filters.NewArgs()
	args.Add("label", LabelManaged+"=true")
	args.Add("label", LabelEnvironment)
	list, err := d.api.ContainerList(ctx, container.ListOptions{Filters: args})
	if err != nil {
		return 0, fmt.Errorf("dockerx: list environment containers: %w", err)
	}
	n := 0
	for _, c := range list {
		// Defence in depth, as KillByLabels already does: only count a
		// container that really does carry both labels.
		if isManagedEnv(c.Labels) {
			n++
		}
	}
	return n, nil
}

// isManagedEnv reports whether labels mark an object (container or volume)
// as one this package created and may act on.
func isManagedEnv(labels map[string]string) bool {
	return labels[LabelManaged] == "true" && labels[LabelEnvironment] != ""
}
