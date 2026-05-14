package proxy

import (
	"context"
	"io"
	"strings"
)

// goawayBody wraps an SSE response body and handles upstream HTTP/2 GOAWAY
// connection rotations transparently.
//
// When the upstream closes mid-stream with "use of closed network connection"
// (the Go HTTP/2 transport's GOAWAY signal):
//   - If no bytes have been read yet: re-issue the request on the fresh
//     connection the transport opens and continue seamlessly.
//   - If bytes were already read: return io.EOF so the downstream receives a
//     clean truncated response instead of ERR_CONNECTION_CLOSED.
type goawayBody struct {
	body      io.ReadCloser
	reissue   func() (io.ReadCloser, error)
	ctx       context.Context // upstream request context; if cancelled, don't treat as GOAWAY
	bytesRead int64
	retried   bool
}

// isGoawayErr returns true only when err signals an HTTP/2 GOAWAY-type
// connection rotation — not a context cancellation or other explicit close.
func isGoawayErr(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	// Context cancellation (VS Code RST_STREAM, request timeout, etc.) must
	// not be mistaken for a GOAWAY: the caller deliberately closed the request.
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "GOAWAY")
}

func (g *goawayBody) Read(p []byte) (int, error) {
	n, err := g.body.Read(p)
	if n > 0 {
		g.bytesRead += int64(n)
	}
	if err == nil || !isGoawayErr(g.ctx, err) {
		return n, err
	}

	// GOAWAY or closed-connection error from upstream (not a context cancel).
	if g.bytesRead == 0 && !g.retried && g.reissue != nil {
		// No data piped yet — safe to replay on the new connection.
		newBody, retryErr := g.reissue()
		if retryErr == nil {
			g.body.Close()
			g.body = newBody
			g.retried = true
			// Read from the new body for this call.
			rn, rerr := g.body.Read(p)
			if rn > 0 {
				g.bytesRead += int64(rn)
			}
			return rn, rerr
		}
	}

	// Bytes already piped, or retry unavailable/failed: signal clean EOF so
	// the downstream gets a complete (truncated) response instead of a broken pipe.
	return n, io.EOF
}

func (g *goawayBody) Close() error {
	return g.body.Close()
}
