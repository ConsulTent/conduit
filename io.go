package conduit

import (
	"fmt"
	"io"
)

// LimitedReader is an io.Reader that enforces a maximum read limit.
// It never reads past 'limit' bytes; further reads return an error until Reset is called.
//
// This is useful for preventing large malicious payloads from consuming too much memory.
type LimitedReader struct {
	r        io.Reader
	limit    int64
	consumed int64
}

// NewLimitedReader creates a new LimitedReader that wraps the provided io.Reader 'r'
// and enforces a maximum allowed read size of 'limit' bytes.
func NewLimitedReader(r io.Reader, limit int64) *LimitedReader {
	return &LimitedReader{
		r:     r,
		limit: limit,
	}
}

// Read reads up to len(p) bytes into p from the underlying reader, never past the limit.
// Once the limit has been consumed, it returns 0 bytes and an error.
func (l *LimitedReader) Read(p []byte) (n int, err error) {
	remaining := l.limit - l.consumed
	if remaining <= 0 {
		return 0, fmt.Errorf("message size exceeds limit of %d bytes", l.limit)
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err = l.r.Read(p)
	l.consumed += int64(n)
	return n, err
}

// Reset clears the consumed byte count so the limit applies afresh, e.g. to the next message.
func (l *LimitedReader) Reset() {
	l.consumed = 0
}
