package envx

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nvasion/routini-runner/internal/dockerx"
	"github.com/nvasion/routini-runner/internal/egressctl"
)

// networkResult is network.ensure's result.
type networkResult struct {
	Network string `json:"network"`
}

// sessionOpenResult is session.open's result.
type sessionOpenResult struct {
	CaPem string `json:"caPem"`
}

// sessionCloseResult is session.close's result.
type sessionCloseResult struct {
	Egress *egressctl.Stats `json:"egress"`
}

func (m *Manager) volumeEnsure(msg OpMsg, send SendFunc) {
	var a struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	}
	if err := decodeArgs(msg.Args, &a, msg.Op); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), quickOpTimeout)
	defer cancel()
	if err := m.opts.Docker.EnsureVolume(ctx, a.Name, a.Labels); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	send(doneOK(msg.ID, nil))
}

func (m *Manager) volumeRemove(msg OpMsg, send SendFunc) {
	var a struct {
		Name string `json:"name"`
	}
	if err := decodeArgs(msg.Args, &a, msg.Op); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), quickOpTimeout)
	defer cancel()
	if err := m.opts.Docker.RemoveVolume(ctx, a.Name); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	send(doneOK(msg.ID, nil))
}

func (m *Manager) networkEnsure(msg OpMsg, send SendFunc) {
	var a struct {
		Network     string `json:"network"`
		EgressImage string `json:"egressImage"`
	}
	if err := decodeArgs(msg.Args, &a, msg.Op); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	if !allowedImage(a.EgressImage, m.opts.ImagePrefixes) {
		send(doneErr(msg.ID, ImageNotAllowedError(a.EgressImage)))
		return
	}

	d := m.opts.Docker
	ctx, cancel := context.WithTimeout(context.Background(), pullOpTimeout)
	defer cancel()
	if err := d.EnsureImage(ctx, a.EgressImage, dockerx.PullMissing); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	controlURL, err := d.EnsureEgress(ctx, a.EgressImage, m.secret)
	if err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	if err := d.EnsureNetwork(ctx, a.Network, map[string]string{dockerx.LabelManaged: "true"}); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	if err := d.ConnectNetwork(ctx, a.Network, dockerx.EgressContainerName, dockerx.EgressContainerName); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	// Both agentx and envx must use the same secret for EnsureEgress to see
	// one stable routini-egress instead of recreating it every time the two
	// packages take turns calling it with different secrets; the control
	// URL learned here is what session.open and session.close need next.
	m.setControlURL(controlURL)
	send(doneOK(msg.ID, networkResult{Network: a.Network}))
}

func (m *Manager) sessionOpen(msg OpMsg, send SendFunc) {
	var a struct {
		Session json.RawMessage `json:"session"`
	}
	if err := decodeArgs(msg.Args, &a, msg.Op); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	token, err := sessionToken(a.Session)
	if err != nil {
		send(doneErr(msg.ID, "invalid session"))
		return
	}
	if !tokenRe.MatchString(token) {
		send(doneErr(msg.ID, "invalid session token"))
		return
	}
	ctrl, err := m.newControlClient()
	if err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), quickOpTimeout)
	defer cancel()
	// Remember the token before opening it: a Disconnect that lands while the
	// PUT is in flight must still close this session, or the proxy would keep
	// its credentials on an unsupervised host. Closing a session that never
	// opened is harmless.
	m.rememberToken(token)
	if err := ctrl.OpenSession(ctx, token, a.Session); err != nil {
		m.forgetToken(token)
		send(doneErr(msg.ID, err.Error()))
		return
	}

	pem, err := ctrl.CA(ctx)
	if err != nil {
		// The session was opened but its CA could not be read: close it
		// again on the way out so the proxy does not keep holding
		// credentials for a session the runner has already given up on.
		m.forgetToken(token)
		cctx, ccancel := context.WithTimeout(context.Background(), quickOpTimeout)
		_, _ = ctrl.CloseSession(cctx, token)
		ccancel()
		send(doneErr(msg.ID, err.Error()))
		return
	}
	send(doneOK(msg.ID, sessionOpenResult{CaPem: pem}))
}

func (m *Manager) sessionClose(msg OpMsg, send SendFunc) {
	var a struct {
		Token string `json:"token"`
	}
	if err := decodeArgs(msg.Args, &a, msg.Op); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	if !tokenRe.MatchString(a.Token) {
		send(doneErr(msg.ID, "invalid session token"))
		return
	}
	ctrl, err := m.newControlClient()
	if err != nil {
		m.forgetToken(a.Token)
		send(doneErr(msg.ID, err.Error()))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), quickOpTimeout)
	defer cancel()
	stats, err := ctrl.CloseSession(ctx, a.Token)
	m.forgetToken(a.Token)
	if err != nil {
		// The real credentials are what matter here, and the DELETE was
		// still attempted; only the stats could not be read, exactly the
		// way agentx's step 7 treats a failed close (PROTOCOL.md 2.6).
		m.logf("env session close %s: %v", msg.ID, err)
		send(doneOK(msg.ID, sessionCloseResult{Egress: nil}))
		return
	}
	send(doneOK(msg.ID, sessionCloseResult{Egress: stats}))
}

// containerStartResult is container.start's result.
type containerStartResult struct {
	ContainerID string `json:"containerId"`
}

func (m *Manager) containerStart(msg OpMsg, send SendFunc) {
	var a struct {
		Name      string            `json:"name"`
		Image     string            `json:"image"`
		Volume    string            `json:"volume"`
		Labels    map[string]string `json:"labels"`
		Cpus      float64           `json:"cpus"`
		MemoryMb  int64             `json:"memoryMb"`
		PidsLimit int64             `json:"pidsLimit"`
		Network   string            `json:"network"`
		Env       map[string]string `json:"env"`
	}
	if err := decodeArgs(msg.Args, &a, msg.Op); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	if !allowedImage(a.Image, m.opts.ImagePrefixes) {
		send(doneErr(msg.ID, ImageNotAllowedError(a.Image)))
		return
	}

	d := m.opts.Docker
	ctx, cancel := context.WithTimeout(context.Background(), pullOpTimeout)
	defer cancel()

	n, err := d.CountEnvContainers(ctx)
	if err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	if n >= m.opts.MaxEnvironments {
		send(doneErr(msg.ID, BusyError(n)))
		return
	}

	if err := d.EnsureImage(ctx, a.Image, dockerx.PullMissing); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}

	vol, err := d.InspectVolume(ctx, a.Volume)
	if err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	envID := a.Labels[dockerx.LabelEnvironment]
	switch {
	case !vol.Exists:
		send(doneErr(msg.ID, fmt.Sprintf("volume %s does not exist", a.Volume)))
		return
	case envID == "" || vol.Labels[dockerx.LabelEnvironment] != envID:
		send(doneErr(msg.ID, fmt.Sprintf("volume %s does not carry the container's routini.environment label", a.Volume)))
		return
	}

	spec := dockerx.EnvSpec{
		Name:      a.Name,
		Image:     a.Image,
		Volume:    a.Volume,
		Network:   a.Network,
		Runtime:   m.opts.Runtime,
		Labels:    envLabels(a.Labels),
		Env:       a.Env,
		Cpus:      a.Cpus,
		MemoryMb:  a.MemoryMb,
		PidsLimit: a.PidsLimit,
	}
	id, err := d.StartEnvContainer(ctx, spec)
	if err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	send(doneOK(msg.ID, containerStartResult{ContainerID: id}))
}

func (m *Manager) containerRemove(msg OpMsg, send SendFunc) {
	var a struct {
		ContainerID string `json:"containerId"`
	}
	if err := decodeArgs(msg.Args, &a, msg.Op); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), quickOpTimeout)
	defer cancel()
	if err := m.opts.Docker.RemoveEnvContainer(ctx, a.ContainerID); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	send(doneOK(msg.ID, nil))
}

// containerStateResult is container.state's result.
type containerStateResult struct {
	State string `json:"state"`
}

func (m *Manager) containerState(msg OpMsg, send SendFunc) {
	var a struct {
		ContainerID string `json:"containerId"`
	}
	if err := decodeArgs(msg.Args, &a, msg.Op); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), quickOpTimeout)
	defer cancel()
	info, err := m.opts.Docker.InspectEnv(ctx, a.ContainerID)
	if err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	state := "missing"
	switch {
	case info.Exists && info.Managed && info.Running:
		state = "running"
	case info.Exists && info.Managed:
		state = "stopped"
	}
	send(doneOK(msg.ID, containerStateResult{State: state}))
}

func (m *Manager) pull(msg OpMsg, send SendFunc) {
	var a struct {
		Image string `json:"image"`
	}
	if err := decodeArgs(msg.Args, &a, msg.Op); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	if !allowedImage(a.Image, m.opts.ImagePrefixes) {
		send(doneErr(msg.ID, ImageNotAllowedError(a.Image)))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), pullOpTimeout)
	defer cancel()
	if err := m.opts.Docker.EnsureImage(ctx, a.Image, dockerx.PullAlways); err != nil {
		send(doneErr(msg.ID, err.Error()))
		return
	}
	send(doneOK(msg.ID, nil))
}
