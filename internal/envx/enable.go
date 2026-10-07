package envx

import "github.com/nvasion/routini-runner/internal/dockerx"

// daemonRef boxes the Docker client so it can live in an atomic.Pointer.
type daemonRef struct{ d dockerx.Docker }

// Enable switches the Manager on with d. The connection calls it once Docker
// answers after the runner started (the daemon came up late), so environments
// work without a restart. A nil d leaves the Manager disabled.
func (m *Manager) Enable(d dockerx.Docker) {
	if d == nil {
		return
	}
	m.daemon.Store(&daemonRef{d: d})
	m.enabled.Store(true)
}

// docker is the daemon ops run on. Only called once enabled, so it is set.
func (m *Manager) docker() dockerx.Docker {
	if r := m.daemon.Load(); r != nil {
		return r.d
	}
	return nil
}
