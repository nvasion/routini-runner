package conn

import (
	"math/rand"
	"time"
)

// Backoff is the reconnect schedule: exponential from Initial, capped at
// Max, with ±Jitter randomisation, reset once a connection has stayed up
// for ResetAfter.
type Backoff struct {
	Initial    time.Duration
	Max        time.Duration
	Jitter     float64 // fraction, e.g. 0.2 for ±20%
	ResetAfter time.Duration
}

// DefaultBackoff is the schedule from PROTOCOL.md section 2: 1 s doubling to
// 60 s, ±20% jitter, reset after 60 s of uptime.
func DefaultBackoff() Backoff {
	return Backoff{Initial: time.Second, Max: 60 * time.Second, Jitter: 0.2, ResetAfter: 60 * time.Second}
}

// Delay returns the wait before reconnect attempt number attempt (0-based).
// rnd returns a value in [0, 1); nil uses math/rand.
func (b Backoff) Delay(attempt int, rnd func() float64) time.Duration {
	d := b.Initial
	for i := 0; i < attempt && d < b.Max; i++ {
		d *= 2
	}
	if d > b.Max {
		d = b.Max
	}
	if b.Jitter > 0 {
		if rnd == nil {
			rnd = rand.Float64
		}
		d = time.Duration(float64(d) * (1 + b.Jitter*(2*rnd()-1)))
	}
	return d
}
