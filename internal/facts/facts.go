// Package facts gathers host facts from /proc, statfs("/"), uname and the
// network interfaces (PROTOCOL.md section 2.2). Every field is optional and
// omitted when it cannot be read.
package facts

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Facts is the facts object sent in hello and in periodic facts messages.
type Facts struct {
	Kernel      string   `json:"kernel,omitempty"`
	OSPretty    string   `json:"osPretty,omitempty"`
	UptimeSec   *int64   `json:"uptimeSec,omitempty"`
	Load1       *float64 `json:"load1,omitempty"`
	Load5       *float64 `json:"load5,omitempty"`
	Load15      *float64 `json:"load15,omitempty"`
	CPUs        *int     `json:"cpus,omitempty"`
	MemTotalMb  *int64   `json:"memTotalMb,omitempty"`
	MemUsedPct  *int     `json:"memUsedPct,omitempty"`
	DiskTotalGb *float64 `json:"diskTotalGb,omitempty"`
	DiskUsedPct *int     `json:"diskUsedPct,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
	Docker      *Docker  `json:"docker,omitempty"`
	Agents      *Agents  `json:"agents,omitempty"`
}

// Agents says why this runner does or does not serve agents, so a console can
// tell an admin what to do on the host (PROTOCOL.md section 2.2). Like Docker,
// only the control connection fills it in.
type Agents struct {
	// Configured is capabilities.agents in config.json.
	Configured bool `json:"configured"`
	// Error is why Docker did not answer the startup ping, when Configured.
	Error string `json:"error,omitempty"`
}

// Docker reports the local Docker daemon and this runner's agent capacity
// (PROTOCOL.md section 2.2). Collect never fills it in: only the control
// connection knows whether the daemon answered its startup ping and how many
// agent tasks are running, so it attaches this object itself. The whole
// object is omitted when Docker is unreachable.
type Docker struct {
	// Available says whether the daemon answered at the last probe.
	Available bool `json:"available"`
	// Version is what its ping reported.
	Version string `json:"version"`
	// AgentsRunning is the number of agent tasks running now.
	AgentsRunning int `json:"agentsRunning"`
	// MaxAgents is the configured maxConcurrentAgents, so a console can
	// show spare capacity.
	MaxAgents int `json:"maxAgents"`
	// EnvironmentsRunning is the number of environment containers running
	// now.
	EnvironmentsRunning int `json:"environmentsRunning"`
	// MaxEnvironments is the configured maxEnvironments, so a console can
	// show spare capacity.
	MaxEnvironments int `json:"maxEnvironments"`
}

func ptr[T any](v T) *T { return &v }

// Collect reads the current facts from the running system.
func Collect() Facts {
	var f Facts
	if k, err := kernel(); err == nil {
		f.Kernel = k
	}
	if r, err := os.Open("/etc/os-release"); err == nil {
		if p, err := ParseOSRelease(r); err == nil {
			f.OSPretty = p
		}
		r.Close()
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if u, err := ParseUptime(string(b)); err == nil {
			f.UptimeSec = ptr(int64(u))
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if l1, l5, l15, err := ParseLoadavg(string(b)); err == nil {
			f.Load1, f.Load5, f.Load15 = ptr(l1), ptr(l5), ptr(l15)
		}
	}
	f.CPUs = ptr(runtime.NumCPU())
	if r, err := os.Open("/proc/meminfo"); err == nil {
		if totalKB, availKB, err := ParseMeminfo(r); err == nil {
			mb, pct := MemStats(totalKB, availKB)
			f.MemTotalMb, f.MemUsedPct = ptr(mb), ptr(pct)
		}
		r.Close()
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err == nil {
		if gb, pct, ok := DiskStats(uint64(st.Blocks), uint64(st.Bfree), uint64(st.Bavail), uint64(st.Bsize)); ok {
			f.DiskTotalGb, f.DiskUsedPct = ptr(gb), ptr(pct)
		}
	}
	if addrs, err := addresses(); err == nil && len(addrs) > 0 {
		f.Addresses = addrs
	}
	return f
}

// ParseMeminfo returns MemTotal and MemAvailable (in kB) from /proc/meminfo.
func ParseMeminfo(r io.Reader) (totalKB, availKB int64, err error) {
	var haveTotal, haveAvail bool
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, perr := strconv.ParseInt(fields[0], 10, 64)
		if perr != nil {
			continue
		}
		switch key {
		case "MemTotal":
			totalKB, haveTotal = v, true
		case "MemAvailable":
			availKB, haveAvail = v, true
		}
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}
	if !haveTotal || !haveAvail || totalKB <= 0 {
		return 0, 0, errors.New("meminfo: MemTotal or MemAvailable missing")
	}
	return totalKB, availKB, nil
}

// MemStats converts meminfo values to memTotalMb (MiB) and memUsedPct,
// where memUsedPct = (MemTotal - MemAvailable) / MemTotal, rounded.
func MemStats(totalKB, availKB int64) (totalMb int64, usedPct int) {
	totalMb = totalKB / 1024
	used := float64(totalKB - availKB)
	if used < 0 {
		used = 0
	}
	usedPct = int(math.Round(used * 100 / float64(totalKB)))
	return totalMb, usedPct
}

// ParseLoadavg parses the first three fields of /proc/loadavg.
func ParseLoadavg(s string) (l1, l5, l15 float64, err error) {
	f := strings.Fields(s)
	if len(f) < 3 {
		return 0, 0, 0, fmt.Errorf("loadavg: expected at least 3 fields, got %d", len(f))
	}
	vals := make([]float64, 3)
	for i := 0; i < 3; i++ {
		vals[i], err = strconv.ParseFloat(f[i], 64)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("loadavg: %w", err)
		}
	}
	return vals[0], vals[1], vals[2], nil
}

// ParseUptime parses the first field of /proc/uptime, in whole seconds.
func ParseUptime(s string) (int64, error) {
	f := strings.Fields(s)
	if len(f) < 1 {
		return 0, errors.New("uptime: empty")
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, fmt.Errorf("uptime: %w", err)
	}
	if v < 0 {
		return 0, errors.New("uptime: negative")
	}
	return int64(v), nil
}

// ParseOSRelease returns PRETTY_NAME from /etc/os-release content.
func ParseOSRelease(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		key, val, ok := strings.Cut(line, "=")
		if !ok || key != "PRETTY_NAME" {
			continue
		}
		val = unquoteShell(val)
		if val == "" {
			break
		}
		return val, nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("os-release: PRETTY_NAME not found")
}

// unquoteShell removes the shell-style quoting allowed in os-release values.
func unquoteShell(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		q := v[0]
		v = v[1 : len(v)-1]
		if q == '"' {
			var b strings.Builder
			for i := 0; i < len(v); i++ {
				if v[i] == '\\' && i+1 < len(v) && strings.IndexByte("\"\\$`", v[i+1]) >= 0 {
					i++
				}
				b.WriteByte(v[i])
			}
			v = b.String()
		}
	}
	return v
}

// DiskStats converts statfs values (in blocks of bsize bytes) to
// diskTotalGb (GiB, one decimal) and diskUsedPct. Like df, the percentage
// excludes reserved blocks: used = blocks - bfree, pct = used / (used + bavail),
// rounded up to a whole percent as df does.
func DiskStats(blocks, bfree, bavail, bsize uint64) (totalGb float64, usedPct int, ok bool) {
	if blocks == 0 || bsize == 0 || bfree > blocks {
		return 0, 0, false
	}
	totalGb = math.Round(float64(blocks)*float64(bsize)/(1<<30)*10) / 10
	used := blocks - bfree
	denom := used + bavail
	if denom == 0 {
		return totalGb, 0, true
	}
	// df: pct = ceil(used * 100 / (used + avail))
	usedPct = int((used*100 + denom - 1) / denom)
	return totalGb, usedPct, true
}

func kernel() (string, error) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "", err
	}
	sys, rel := cstr(u.Sysname[:]), cstr(u.Release[:])
	if sys == "" {
		return "", errors.New("uname: empty")
	}
	return strings.TrimSpace(sys + " " + rel), nil
}

// cstr converts a NUL-terminated utsname field (int8 or uint8 depending on
// the architecture) to a string.
func cstr[T int8 | uint8](a []T) string {
	b := make([]byte, 0, len(a))
	for _, c := range a {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func addresses() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		out = append(out, FilterAddrs(addrs)...)
	}
	return out, nil
}

// FilterAddrs returns the non-loopback IP addresses in addrs, without prefix lengths.
func FilterAddrs(addrs []net.Addr) []string {
	var out []string
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		out = append(out, ip.String())
	}
	return out
}
