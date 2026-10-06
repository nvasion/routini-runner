package dockerx

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// collectLines writes in using fixed-size chunks, so line joins across writes
// are exercised, and returns the emitted lines.
func collectLines(t *testing.T, in string, chunk int) []string {
	t.Helper()
	var out []string
	w := newLineWriter(func(s string) { out = append(out, s) })
	for i := 0; i < len(in); i += chunk {
		end := i + chunk
		if end > len(in) {
			end = len(in)
		}
		n, err := w.Write([]byte(in[i:end]))
		if err != nil {
			t.Fatalf("Write returned %v, want nil: stdcopy must never stop draining", err)
		}
		if n != end-i {
			t.Fatalf("Write returned %d, want %d", n, end-i)
		}
	}
	w.Flush()
	return out
}

func TestLineWriter(t *testing.T) {
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
			if got := collectLines(t, tc.in, chunk); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("chunk %d, %q: got %q, want %q", chunk, tc.in, got, tc.want)
			}
		}
	}
}

func TestLineWriterSplitsLongLines(t *testing.T) {
	long := strings.Repeat("x", 2*MaxLine+10)
	got := collectLines(t, long+"\nend\n", 4096)
	if len(got) != 4 || len(got[0]) != MaxLine || len(got[1]) != MaxLine || len(got[2]) != 10 || got[3] != "end" {
		lens := make([]int, 0, len(got))
		for _, s := range got {
			lens = append(lens, len(s))
		}
		t.Fatalf("unexpected pieces: %v", lens)
	}

	// A multi-byte rune straddling the limit is not cut in half.
	s := strings.Repeat("a", MaxLine-1) + "é" + "tail"
	got = collectLines(t, s, 1000)
	if len(got) != 2 {
		t.Fatalf("got %d pieces, want 2", len(got))
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

func TestLineWriterFlushIsIdempotent(t *testing.T) {
	var out []string
	w := newLineWriter(func(s string) { out = append(out, s) })
	if _, err := w.Write([]byte("tail")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	w.Flush()
	w.Flush()
	if want := []string{"tail"}; !reflect.DeepEqual(out, want) {
		t.Errorf("got %q, want %q emitted exactly once", out, want)
	}
}
