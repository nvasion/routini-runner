package facts

import (
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"testing"
)

const sampleMeminfo = `MemTotal:        8163328 kB
MemFree:          512000 kB
MemAvailable:    4816363 kB
Buffers:          123456 kB
Cached:          2345678 kB
SwapTotal:       2097148 kB
`

func TestParseMeminfo(t *testing.T) {
	total, avail, err := ParseMeminfo(strings.NewReader(sampleMeminfo))
	if err != nil {
		t.Fatal(err)
	}
	if total != 8163328 || avail != 4816363 {
		t.Fatalf("got total=%d avail=%d", total, avail)
	}
	mb, pct := MemStats(total, avail)
	if mb != 7972 {
		t.Errorf("memTotalMb = %d, want 7972", mb)
	}
	if pct != 41 { // (8163328-4816363)/8163328 = 41.0%
		t.Errorf("memUsedPct = %d, want 41", pct)
	}
	if _, _, err := ParseMeminfo(strings.NewReader("MemTotal: 100 kB\n")); err == nil {
		t.Error("expected an error without MemAvailable")
	}
}

func TestParseLoadavg(t *testing.T) {
	l1, l5, l15, err := ParseLoadavg("0.42 0.30 0.25 2/345 12345\n")
	if err != nil {
		t.Fatal(err)
	}
	if l1 != 0.42 || l5 != 0.30 || l15 != 0.25 {
		t.Fatalf("got %v %v %v", l1, l5, l15)
	}
	if _, _, _, err := ParseLoadavg("0.1 0.2"); err == nil {
		t.Error("expected an error for short input")
	}
	if _, _, _, err := ParseLoadavg("a b c"); err == nil {
		t.Error("expected an error for non-numbers")
	}
}

func TestParseUptime(t *testing.T) {
	u, err := ParseUptime("123456.78 456789.12\n")
	if err != nil || u != 123456 {
		t.Fatalf("got %d, %v", u, err)
	}
	if _, err := ParseUptime(""); err == nil {
		t.Error("expected an error for empty input")
	}
}

func TestParseOSRelease(t *testing.T) {
	cases := map[string]string{
		"NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n": "Ubuntu 24.04.1 LTS",
		"PRETTY_NAME='Debian GNU/Linux 12 (bookworm)'\n":                                         "Debian GNU/Linux 12 (bookworm)",
		"PRETTY_NAME=Alpine\n":                     "Alpine",
		"PRETTY_NAME=\"Say \\\"hi\\\" \\$HOME\"\n": `Say "hi" $HOME`,
	}
	for in, want := range cases {
		got, err := ParseOSRelease(strings.NewReader(in))
		if err != nil || got != want {
			t.Errorf("ParseOSRelease(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseOSRelease(strings.NewReader("NAME=x\n")); err == nil {
		t.Error("expected an error without PRETTY_NAME")
	}
}

func TestDiskStats(t *testing.T) {
	// A typical ext4 root: 4 KiB blocks, 5% reserved.
	// df: Used = 20,000,000-7,000,000 = 13,000,000 blocks; Avail = 5,971,000;
	// Use% = ceil(13,000,000*100 / 18,971,000) = ceil(68.52) = 69%.
	gb, pct, ok := DiskStats(20_000_000, 7_000_000, 5_971_000, 4096)
	if !ok {
		t.Fatal("not ok")
	}
	if gb != 76.3 { // 20e6*4096 / 2^30 = 76.29
		t.Errorf("diskTotalGb = %v, want 76.3", gb)
	}
	if pct != 69 {
		t.Errorf("diskUsedPct = %d, want 69", pct)
	}
	// Exact percentages are not rounded up.
	if _, pct, _ := DiskStats(100, 50, 50, 4096); pct != 50 {
		t.Errorf("diskUsedPct = %d, want 50", pct)
	}
	if _, _, ok := DiskStats(0, 0, 0, 4096); ok {
		t.Error("expected !ok for zero blocks")
	}
}

func TestFilterAddrs(t *testing.T) {
	mk := func(s string) net.Addr {
		ip, n, _ := net.ParseCIDR(s)
		n.IP = ip
		return n
	}
	got := FilterAddrs([]net.Addr{mk("127.0.0.1/8"), mk("10.0.0.11/24"), mk("::1/128"), mk("fd00::11/64")})
	want := []string{"10.0.0.11", "fd00::11"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCollectOmitsMissingAndMarshals(t *testing.T) {
	f := Collect()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["cpus"]; !ok {
		t.Error("cpus missing")
	}
	if k, _ := m["kernel"].(string); !strings.HasPrefix(k, "Linux ") {
		t.Errorf("kernel = %q", k)
	}
	// An empty Facts marshals to {} (every field optional).
	b, _ = json.Marshal(Facts{})
	if string(b) != "{}" {
		t.Errorf("empty facts marshal to %s", b)
	}
}
