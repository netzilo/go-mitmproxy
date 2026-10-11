package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
)

// slowResponseAddon holds every response in the Response hook for a while,
// as an inspecting addon does.
type slowResponseAddon struct{ BaseAddon }

func (*slowResponseAddon) Response(f *Flow) { time.Sleep(300 * time.Millisecond) }

// A client that asks to close (Connection: close) gets its whole response
// though the upstream closes its connection without echoing it, while the
// response is still in the Response hook.
func TestCloseRequestedUpstreamClosesSilently(t *testing.T) {
	ca, err := cert.NewSelfSignCAMemory()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.GetCert("localhost")
	if err != nil {
		t.Fatal(err)
	}
	upLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*leaf}})
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				// No Connection: close in the answer; the connection just ends.
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"ok\":\"whole\"}\n")) //nolint:errcheck
			}(c)
		}
	}()

	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := pl.Addr().String()
	pl.Close()
	p, err := NewProxy(&Options{Addr: addr, SslInsecure: true, StreamLargeBodies: 1024 * 1024 * 10})
	if err != nil {
		t.Fatal(err)
	}
	p.AddAddon(&slowResponseAddon{})
	go p.Start() //nolint:errcheck
	defer p.Close()
	time.Sleep(200 * time.Millisecond)

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           func(*http.Request) (*url.URL, error) { return url.Parse("http://" + addr) },
	}}
	port := upLn.Addr().(*net.TCPAddr).Port
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodPost, "https://localhost:"+strconv.Itoa(port)+"/v1/chat", nil)
		req.Close = true
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(body) != "{\"ok\":\"whole\"}\n" {
			t.Fatalf("request %d: body %q err %v", i, body, err)
		}
	}
}
