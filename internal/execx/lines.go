package execx

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf8"
)

// MaxLine is the longest piece of a line sent in one exec.output frame.
const MaxLine = 16 * 1024

// lineSplitter turns a byte stream into lines as PROTOCOL.md 2.3 requires:
// split on \n, strip a trailing \r, replace invalid UTF-8 with U+FFFD, split
// lines longer than MaxLine into MaxLine pieces, and flush an unterminated
// final line at EOF.
type lineSplitter struct {
	pending []byte
	emit    func(string)
}

func (s *lineSplitter) write(p []byte) {
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			s.pending = append(s.pending, p...)
			s.splitLong()
			return
		}
		s.pending = append(s.pending, p[:i]...)
		p = p[i+1:]
		s.pending = bytes.TrimSuffix(s.pending, []byte{'\r'})
		s.splitLong()
		s.emitBytes(s.pending)
		s.pending = s.pending[:0]
	}
}

// splitLong emits MaxLine-sized pieces while the pending line is too long,
// cutting at a UTF-8 rune boundary when one is within 3 bytes of the limit.
func (s *lineSplitter) splitLong() {
	for len(s.pending) > MaxLine {
		cut := MaxLine
		for back := 0; back < utf8.UTFMax && cut-back > 0; back++ {
			if utf8.RuneStart(s.pending[cut-back]) {
				cut -= back
				break
			}
		}
		s.emitBytes(s.pending[:cut])
		n := copy(s.pending, s.pending[cut:])
		s.pending = s.pending[:n]
	}
}

// flush emits an unterminated final line, if any.
func (s *lineSplitter) flush() {
	if len(s.pending) == 0 {
		return
	}
	s.pending = bytes.TrimSuffix(s.pending, []byte{'\r'})
	s.emitBytes(s.pending)
	s.pending = s.pending[:0]
}

func (s *lineSplitter) emitBytes(b []byte) {
	s.emit(strings.ToValidUTF8(string(b), "�"))
}

// splitLines reads r to EOF (or error), calling emit once per line.
func splitLines(r io.Reader, emit func(string)) {
	s := &lineSplitter{emit: emit}
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			s.write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	s.flush()
}
