package proxy

import "testing"

func TestSSEHeartbeatBoundarySafety(t *testing.T) {
	tail := []byte(nil)
	if !endsAtSSEEventBoundary(tail) {
		t.Fatal("empty SSE tail should be heartbeat safe")
	}

	tail = updateSSETail(tail, []byte("data: hello\n"))
	if endsAtSSEEventBoundary(tail) {
		t.Fatal("single newline inside an SSE event should not be heartbeat safe")
	}

	tail = updateSSETail(tail, []byte("\n"))
	if !endsAtSSEEventBoundary(tail) {
		t.Fatal("split LF event boundary should be heartbeat safe")
	}

	tail = updateSSETail(nil, []byte("data: hello\r"))
	if endsAtSSEEventBoundary(tail) {
		t.Fatal("partial CRLF event boundary should not be heartbeat safe")
	}

	tail = updateSSETail(tail, []byte("\n\r\n"))
	if !endsAtSSEEventBoundary(tail) {
		t.Fatal("split CRLF event boundary should be heartbeat safe")
	}

	tail = updateSSETail(tail, rawSSEHeartbeat)
	if !endsAtSSEEventBoundary(tail) {
		t.Fatal("raw SSE heartbeat must leave the stream at an event boundary")
	}
}
