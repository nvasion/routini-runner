package execx

import (
	"io"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// chunkReader returns its data in fixed-size reads to exercise line joins.
type chunkReader struct {
	data []byte
	n    int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := c.n
	if n > len(c.data) {
		n = len(c.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func collect(in string, chunk int) []string {
	var out []string
	splitLines(&chunkReader{data: []byte(in), n: chunk}, func(s string) { out = append(out, s) })
	return out
}

func TestSplitLines(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a\nb\n", []string{"a", "b"}},
		{"a\r\nb\r\n", []string{"a", "b"}},
		{"a\n\nb", []string{"a", "", "b"}},
		{"no newline", []string{"no newline"}},
		{"cr\r", []string{"cr"}},
		{"bad\xffutf8\n", []string{"bad�utf8"}},
		{"", nil},
	}
	for _, chunk := range []int{1, 3, 1 << 20} {
		for _, tc := range cases {
			if got := collect(tc.in, chunk); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("chunk %d, %q: got %q, want %q", chunk, tc.in, got, tc.want)
			}
		}
	}
}

func TestSplitLongLines(t *testing.T) {
	long := strings.Repeat("x", 2*MaxLine+10)
	got := collect(long+"\nend\n", 4096)
	if len(got) != 4 || len(got[0]) != MaxLine || len(got[1]) != MaxLine || len(got[2]) != 10 || got[3] != "end" {
		lens := []int{}
		for _, s := range got {
			lens = append(lens, len(s))
		}
		t.Fatalf("unexpected pieces: %v", lens)
	}

	// A multi-byte rune straddling the limit is not cut in half.
	s := strings.Repeat("a", MaxLine-1) + "é" + "tail"
	got = collect(s, 1000)
	if len(got) != 2 {
		t.Fatalf("got %d pieces", len(got))
	}
	for _, p := range got {
		if !utf8.ValidString(p) || strings.ContainsRune(p, utf8.RuneError) {
			t.Errorf("piece is not clean UTF-8: %q...", p[:10])
		}
	}
	if got[0]+got[1] != s {
		t.Error("pieces do not reassemble the line")
	}
}

func TestMergeEnv(t *testing.T) {
	got := MergeEnv([]string{"A=1", "B=2", "A=3"}, map[string]string{"B": "x", "C": "y"})
	want := []string{"A=3", "B=x", "C=y"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestTimeoutFor(t *testing.T) {
	i := func(v int) *int { return &v }
	cases := []struct {
		in   *int
		want int
	}{{nil, 600}, {i(0), 600}, {i(-5), 600}, {i(30), 30}, {i(86400), 86400}, {i(100000), 86400}}
	for _, tc := range cases {
		if got := timeoutFor(tc.in); got.Seconds() != float64(tc.want) {
			t.Errorf("timeoutFor(%v) = %v, want %ds", tc.in, got, tc.want)
		}
	}
}

func TestEnvKeyRule(t *testing.T) {
	for _, k := range []string{"FOO", "_x", "a1_B"} {
		if !envKeyRe.MatchString(k) {
			t.Errorf("%q should be valid", k)
		}
	}
	for _, k := range []string{"", "1A", "A-B", "A B", "A=B", "É"} {
		if envKeyRe.MatchString(k) {
			t.Errorf("%q should be invalid", k)
		}
	}
}
