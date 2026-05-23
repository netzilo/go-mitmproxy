package proxy

import (
	"context"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

func countAttackerAcceptGoroutines() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "(*attackerListener).Accept")
}

// TestShutdownStopsAttacker verifies that Shutdown/Close end the attacker's
// Serve goroutine, which used to block forever on the connection channel.
func TestShutdownStopsAttacker(t *testing.T) {
	for _, graceful := range []bool{true, false} {
		dir := t.TempDir()
		p, err := NewProxy(&Options{Addr: "127.0.0.1:0", CaRootPath: dir})
		if err != nil {
			t.Fatal(err)
		}
		go p.Start() //nolint:errcheck
		deadline := time.Now().Add(2 * time.Second)
		for countAttackerAcceptGoroutines() == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if countAttackerAcceptGoroutines() == 0 {
			t.Fatal("attacker never started")
		}
		if graceful {
			err = p.Shutdown(context.Background())
		} else {
			err = p.Close()
		}
		if err != nil {
			t.Fatalf("stop (graceful=%v): %v", graceful, err)
		}
		deadline = time.Now().Add(2 * time.Second)
		for countAttackerAcceptGoroutines() != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if n := countAttackerAcceptGoroutines(); n != 0 {
			t.Fatalf("graceful=%v: %d attacker Accept goroutines still alive", graceful, n)
		}
		// A late intercepted connection must be dropped, not block.
		c1, c2 := net.Pipe()
		done := make(chan bool, 1)
		go func() { done <- p.attacker.listener.accept(c1) }()
		select {
		case ok := <-done:
			if ok {
				t.Fatal("accept after close reported success")
			}
		case <-time.After(time.Second):
			t.Fatal("accept after close blocked")
		}
		c1.Close()
		c2.Close()
	}
}
