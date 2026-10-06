package dockerx

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// MaxLine is the longest piece of a line passed to a RunStreaming callback.
const MaxLine = 16 * 1024

// lineWriter splits a container output stream into lines under the rules of
// PROTOCOL.md 2.3: split on \n, strip a trailing \r, replace invalid UTF-8
// with U+FFFD, cut lines longer than MaxLine into MaxLine pieces, and flush an
// unterminated final line at the end of the stream.
//
// It is an io.Writer so stdcopy can demultiplex straight into it. The same
// rules are implemented for pipes in internal/execx; that version reads an
// io.Reader to EOF and is deliberately left untouched, since exec and pty
// behaviour must not change.
type lineWriter struct {
	pending []byte
	emit    func(string)
}

func newLineWriter(emit func(string)) *lineWriter {
	return &lineWriter{emit: emit}
}

// Write never fails: stdcopy must keep draining the stream even if a line
// cannot be delivered, otherwise the container would block on its own output.
func (w *lineWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			w.pending = append(w.pending, p...)
			w.splitLong()
			return n, nil
		}
		w.pending = append(w.pending, p[:i]...)
		p = p[i+1:]
		w.pending = bytes.TrimSuffix(w.pending, []byte{'\r'})
		w.splitLong()
		w.emitBytes(w.pending)
		w.pending = w.pending[:0]
	}
	return n, nil
}

// splitLong emits MaxLine-sized pieces while the pending line is too long,
// cutting at a UTF-8 rune boundary when one is within 3 bytes of the limit.
func (w *lineWriter) splitLong() {
	for len(w.pending) > MaxLine {
		cut := MaxLine
		for back := 0; back < utf8.UTFMax && cut-back > 0; back++ {
			if utf8.RuneStart(w.pending[cut-back]) {
				cut -= back
				break
			}
		}
		w.emitBytes(w.pending[:cut])
		n := copy(w.pending, w.pending[cut:])
		w.pending = w.pending[:n]
	}
}

// Flush emits an unterminated final line, if any.
func (w *lineWriter) Flush() {
	if len(w.pending) == 0 {
		return
	}
	w.pending = bytes.TrimSuffix(w.pending, []byte{'\r'})
	w.emitBytes(w.pending)
	w.pending = w.pending[:0]
}

func (w *lineWriter) emitBytes(b []byte) {
	w.emit(strings.ToValidUTF8(string(b), "�"))
}
