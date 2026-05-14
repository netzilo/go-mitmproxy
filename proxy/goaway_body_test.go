package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

type scriptedRead struct {
	data string
	err  error
}

type scriptedReadCloser struct {
	reads  []scriptedRead
	closed bool
}

func (s *scriptedReadCloser) Read(p []byte) (int, error) {
	if len(s.reads) == 0 {
		return 0, io.EOF
	}
	next := s.reads[0]
	s.reads = s.reads[1:]
	n := copy(p, next.data)
	return n, next.err
}

func (s *scriptedReadCloser) Close() error {
	s.closed = true
	return nil
}

func TestGoawayBodyRetriesConsecutiveGoawaysBeforeBytes(t *testing.T) {
	goawayErr := errors.New("http2: received GOAWAY")
	bodies := []*scriptedReadCloser{
		{reads: []scriptedRead{{err: goawayErr}}},
		{reads: []scriptedRead{{err: goawayErr}}},
		{reads: []scriptedRead{{data: "ok"}}},
	}
	reissues := 0
	body := &goawayBody{
		body:        bodies[0],
		ctx:         context.Background(),
		retriesLeft: 2,
		reissue: func() (io.ReadCloser, error) {
			reissues++
			return bodies[reissues], nil
		},
	}

	buf := make([]byte, 8)
	n, err := body.Read(buf)
	if err != nil {
		t.Fatalf("Read returned unexpected error: %v", err)
	}
	if got := string(buf[:n]); got != "ok" {
		t.Fatalf("Read = %q, want ok", got)
	}
	if reissues != 2 {
		t.Fatalf("reissues = %d, want 2", reissues)
	}
	if !bodies[0].closed || !bodies[1].closed {
		t.Fatal("retried bodies were not closed")
	}
}

func TestGoawayBodyDoesNotRetryAfterBytes(t *testing.T) {
	body := &goawayBody{
		body:        &scriptedReadCloser{reads: []scriptedRead{{data: "x", err: errors.New("GOAWAY")}}},
		ctx:         context.Background(),
		retriesLeft: 1,
		reissue: func() (io.ReadCloser, error) {
			t.Fatal("reissue called after bytes were read")
			return nil, nil
		},
	}

	buf := make([]byte, 8)
	n, err := body.Read(buf)
	if err != io.EOF {
		t.Fatalf("Read err = %v, want io.EOF", err)
	}
	if got := string(buf[:n]); got != "x" {
		t.Fatalf("Read = %q, want x", got)
	}
}

func TestCanReplayRequestAllowsOnlySafeMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace} {
		if !canReplayRequest(method) {
			t.Fatalf("%s should be replayable", method)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
		if canReplayRequest(method) {
			t.Fatalf("%s should not be replayable", method)
		}
	}
}
