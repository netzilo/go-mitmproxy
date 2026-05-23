package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

type attackerListener struct {
	connChan chan net.Conn
}

func (l *attackerListener) accept(conn net.Conn) {
	l.connChan <- conn
}

func (l *attackerListener) Accept() (net.Conn, error) {
	c := <-l.connChan
	return c, nil
}
func (l *attackerListener) Close() error   { return nil }
func (l *attackerListener) Addr() net.Addr { return nil }

type attackerConn struct {
	net.Conn
	connCtx *ConnContext
}

type attacker struct {
	proxy        *Proxy
	ca           cert.CA
	server       *http.Server
	h2Server     *http2.Server
	client       *http.Client
	streamClient *http.Client
	listener     *attackerListener
}

func newAttacker(proxy *Proxy) (*attacker, error) {
	ca, err := newCa(proxy.Opts)
	if err != nil {
		return nil, err
	}

	baseTransport := func(forceH2, disableKeepAlives bool) *http.Transport {
		return &http.Transport{
			// When upstreamDialer is set use it directly (no CONNECT proxy overhead);
			// otherwise fall back to the configured upstream proxy.
			Proxy: func(req *http.Request) (*url.URL, error) {
				if proxy.upstreamDialer != nil {
					return nil, nil
				}
				return proxy.realUpstreamProxy()(req)
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if proxy.upstreamDialer != nil {
					return proxy.upstreamDialer(ctx, network, addr)
				}
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			ForceAttemptHTTP2:  forceH2,
			DisableCompression: true,
			DisableKeepAlives:  disableKeepAlives,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: proxy.Opts.SslInsecure,
				KeyLogWriter:       helper.GetTlsKeyLogWriter(),
			},
		}
	}
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		// 禁止自动重定向
		return http.ErrUseLastResponse
	}
	newUpstreamClient := func(forceH2, disableKeepAlives bool) *http.Client {
		return &http.Client{
			Transport:     baseTransport(forceH2, disableKeepAlives),
			CheckRedirect: checkRedirect,
		}
	}

	a := &attacker{
		proxy:        proxy,
		ca:           ca,
		client:       newUpstreamClient(true, false),
		streamClient: newUpstreamClient(true, true),
		listener: &attackerListener{
			connChan: make(chan net.Conn),
		},
	}

	a.server = &http.Server{
		Handler: a,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*attackerConn).connCtx)
		},
	}

	a.h2Server = &http2.Server{
		MaxConcurrentStreams: 100, // todo: wait for remote server setting
		NewWriteScheduler:    func() http2.WriteScheduler { return http2.NewPriorityWriteScheduler(nil) },
	}

	return a, nil
}

func newCa(opts *Options) (cert.CA, error) {
	newCaFunc := opts.NewCaFunc
	if newCaFunc != nil {
		return newCaFunc()
	}
	return cert.NewSelfSignCA(opts.CaRootPath)
}

func (a *attacker) start() error {
	return a.server.Serve(a.listener)
}

func (a *attacker) serveConn(clientTlsConn *tls.Conn, connCtx *ConnContext) {
	connCtx.ClientConn.NegotiatedProtocol = clientTlsConn.ConnectionState().NegotiatedProtocol

	if connCtx.ClientConn.NegotiatedProtocol == "h2" {
		// Create the h2 session context before setting up the upstream client so
		// that DialTLSContext reconnects can use the session lifetime rather than
		// a per-stream context.  A canceled stream (RST_STREAM) must not abort
		// the shared upstream transport reconnection.
		sessionCtx := context.WithValue(context.Background(), connContextKey, connCtx)
		sessionCtx, sessionCancel := context.WithCancel(sessionCtx)

		if connCtx.ServerConn != nil {
			// First-dial path (UpstreamCert mode): a real TLS connection to the
			// server was established before the client handshake.  Use a bare
			// http2.Transport so we get H2 multiplexing upstream, and install a
			// DialTLSContext that re-dials a fresh connection after GOAWAY.
			var dialMu sync.Mutex
			firstDial := true
			connCtx.ServerConn.client = &http.Client{
				Transport: &http2.Transport{
					DialTLSContext: func(_ context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
						dialMu.Lock()
						first := firstDial
						firstDial = false
						dialMu.Unlock()

						if first {
							return connCtx.ServerConn.tlsConn, nil
						}

						// Use the h2 session context, not the per-stream context
						// passed in: an individual stream cancellation (client
						// RST_STREAM) must not prevent the shared upstream transport
						// from reconnecting after GOAWAY or a stale idle connection.
						fakeReq := &http.Request{URL: &url.URL{Scheme: "https", Host: addr}}
						rawConn, err := a.proxy.dialRawConn(sessionCtx, network, addr, fakeReq)
						if err != nil {
							return nil, err
						}
						conn, err := chromeTLSDial(sessionCtx, rawConn, cfg)
						if err != nil {
							rawConn.Close()
							return nil, err
						}
						return conn, nil
					},
					// TLSClientConfig is required so cfg.NextProtos is non-empty when
					// chromeTLSDial evaluates it on GOAWAY reconnects.  Without it,
					// chromeTLSDial falls back to ["http/1.1"] and the upstream
					// negotiates HTTP/1.1, breaking the http2.Transport session for
					// all pending requests.
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: a.proxy.Opts.SslInsecure,
						KeyLogWriter:       helper.GetTlsKeyLogWriter(),
						NextProtos:         []string{"h2"},
					},
					DisableCompression:        true,
					MaxHeaderListSize:         262144, // Chrome SETTINGS_MAX_HEADER_LIST_SIZE
					MaxDecoderHeaderTableSize: 65536,  // Chrome SETTINGS_HEADER_TABLE_SIZE
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		} else {
			// Lazy path: create a single shared H2 transport for all requests on
			// this session.  A background goroutine pre-dials TCP+TLS immediately
			// (while the client H2 SETTINGS exchange is in progress) so the
			// upstream connection is ready before the first request arrives,
			// eliminating the serial dial latency that causes Cursor to RST_STREAM
			// before seeing response HEADERS.
			sni := tlsServerName(connCtx, connCtx.ClientConn.clientHello.ServerName)
			proxy := a.proxy

			// Pre-dial: TCP+TLS in background using the session context so
			// individual stream cancellations don't abort the connection.
			type preDialResult struct {
				conn net.Conn
				err  error
			}
			preDialCh := make(chan preDialResult, 1)
			go func() {
				addr := net.JoinHostPort(sni, "443")
				fakeReq := &http.Request{URL: &url.URL{Scheme: "https", Host: addr}}
				rawConn, err := proxy.dialRawConn(sessionCtx, "tcp", addr, fakeReq)
				if err != nil {
					preDialCh <- preDialResult{err: err}
					return
				}
				tlsCfg := &tls.Config{
					InsecureSkipVerify: proxy.Opts.SslInsecure,
					KeyLogWriter:       helper.GetTlsKeyLogWriter(),
					NextProtos:         []string{"h2"},
					ServerName:         sni,
				}
				conn, err := chromeTLSDial(sessionCtx, rawConn, tlsCfg)
				if err != nil {
					rawConn.Close()
					preDialCh <- preDialResult{err: err}
					return
				}
				preDialCh <- preDialResult{conn: conn}
			}()
			// Cleanup: drain pre-dialed conn if never claimed by DialTLSContext.
			go func() {
				<-sessionCtx.Done()
				select {
				case r := <-preDialCh:
					if r.conn != nil {
						r.conn.Close()
					}
				case <-time.After(2 * time.Second):
				}
			}()

			var preDialOnce sync.Once
			serverConn := newServerConn()
			serverConn.Address = sni
			serverConn.client = &http.Client{
				Transport: &http2.Transport{
					DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
						var usePreDial bool
						preDialOnce.Do(func() { usePreDial = true })
						if usePreDial {
							select {
							case r := <-preDialCh:
								if r.err == nil {
									return r.conn, nil
								}
								// pre-dial failed; fall through to fresh dial
							case <-time.After(500 * time.Millisecond):
								// pre-dial still in progress; fall through to fresh dial
							}
						}
						fakeReq := &http.Request{URL: &url.URL{Scheme: "https", Host: addr}}
						rawConn, err := proxy.dialRawConn(sessionCtx, "tcp", addr, fakeReq)
						if err != nil {
							return nil, err
						}
						conn, err := chromeTLSDial(sessionCtx, rawConn, cfg)
						if err != nil {
							rawConn.Close()
							return nil, err
						}
						return conn, nil
					},
					// TLSClientConfig is the source for cfg passed to DialTLSContext above;
					// chromeTLSDial reads InsecureSkipVerify and KeyLogWriter from it.
					// NextProtos must include "h2" so cfg.NextProtos is non-empty when
					// chromeTLSDial evaluates it; without this it falls back to ["http/1.1"]
					// and the upstream negotiates HTTP/1.1 instead of h2.
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: proxy.Opts.SslInsecure,
						KeyLogWriter:       helper.GetTlsKeyLogWriter(),
						NextProtos:         []string{"h2"},
					},
					DisableCompression:        true,
					MaxHeaderListSize:         262144, // Chrome SETTINGS_MAX_HEADER_LIST_SIZE
					MaxDecoderHeaderTableSize: 65536,  // Chrome SETTINGS_HEADER_TABLE_SIZE
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			connCtx.ServerConn = serverConn
			for _, addon := range proxy.Addons {
				addon.ServerConnected(connCtx)
			}
			// dialFn intentionally not set: ServerConn is pre-configured with a
			// shared H2 transport; attack() uses it directly without re-dialing.
		}

		go func() {
			<-connCtx.ClientConn.Conn.(*wrapClientConn).closeChan
			sessionCancel()
		}()
		go func() {
			a.h2Server.ServeConn(clientTlsConn, &http2.ServeConnOpts{
				Context:    sessionCtx,
				Handler:    a,
				BaseConfig: a.server,
			})
		}()
		return
	}

	a.listener.accept(&attackerConn{
		Conn:    clientTlsConn,
		connCtx: connCtx,
	})
}

func (a *attacker) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if strings.EqualFold(req.Header.Get("Connection"), "Upgrade") && strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		if err := a.proxy.webSocketHandler.handleWSS(res, req); err != nil {
			log.Errorf("handleWSS error: %v", err)
		}
		return
	}

	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	a.attack(res, req)
}

func (a *attacker) initHttpDialFn(req *http.Request) {
	connCtx := req.Context().Value(connContextKey).(*ConnContext)
	connCtx.dialFn = func(ctx context.Context) error {
		addr := helper.CanonicalAddr(req.URL)
		c, err := a.proxy.getUpstreamConn(ctx, req)
		if err != nil {
			return err
		}
		proxy := a.proxy
		cw := &wrapServerConn{
			Conn:    c,
			proxy:   proxy,
			connCtx: connCtx,
		}

		serverConn := newServerConn()
		serverConn.Conn = cw
		serverConn.Address = addr
		serverConn.client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return cw, nil
				},
				ForceAttemptHTTP2:  false, // disable http2
				DisableCompression: true,  // To get the original response from the server, set Transport.DisableCompression to true.
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// 禁止自动重定向
				return http.ErrUseLastResponse
			},
		}

		connCtx.ServerConn = serverConn
		for _, addon := range proxy.Addons {
			addon.ServerConnected(connCtx)
		}

		return nil
	}
}

// send clientHello to server, server handshake
func (a *attacker) serverTlsHandshake(ctx context.Context, connCtx *ConnContext) error {
	proxy := a.proxy
	clientHello := connCtx.ClientConn.clientHello
	serverConn := connCtx.ServerConn
	serverName := tlsServerName(connCtx, clientHello.ServerName)

	// When the client negotiated HTTP/1.1 with us, don't offer h2 to the upstream.
	// If we do, the server may negotiate h2 but serverConn.client uses http.Transport
	// which reads h2 SETTINGS frames as HTTP/1.1 → "malformed HTTP response".
	nextProtos := clientHello.SupportedProtos
	if connCtx.ClientConn.NegotiatedProtocol == "http/1.1" {
		filtered := nextProtos[:0:0]
		for _, p := range nextProtos {
			if p != "h2" {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) == 0 {
			filtered = []string{"http/1.1"}
		}
		nextProtos = filtered
	}

	serverTlsConfig := &tls.Config{
		InsecureSkipVerify: proxy.Opts.SslInsecure,
		KeyLogWriter:       helper.GetTlsKeyLogWriter(),
		ServerName:         serverName,
		NextProtos:         nextProtos,
		// CurvePreferences:   clientHello.SupportedCurves, // todo: 如果打开会出错
		CipherSuites: clientHello.CipherSuites,
	}
	if len(clientHello.SupportedVersions) > 0 {
		minVersion := clientHello.SupportedVersions[0]
		maxVersion := clientHello.SupportedVersions[0]
		for _, version := range clientHello.SupportedVersions {
			if version < minVersion {
				minVersion = version
			}
			if version > maxVersion {
				maxVersion = version
			}
		}
		serverTlsConfig.MinVersion = minVersion
		serverTlsConfig.MaxVersion = maxVersion
	}
	serverTlsConn, err := chromeTLSDial(ctx, serverConn.Conn, serverTlsConfig)
	if err != nil {
		return err
	}
	serverConn.tlsConn = serverTlsConn
	serverTlsState := serverTlsConn.ConnectionState()
	serverConn.tlsState = &serverTlsState
	for _, addon := range proxy.Addons {
		addon.TlsEstablishedServer(connCtx)
	}

	var (
		dialMu    sync.Mutex
		firstDial = true
	)
	reconnectFn := func(ctx context.Context, addr string) (net.Conn, error) {
		fakeReq := &http.Request{URL: &url.URL{Scheme: "https", Host: addr}}
		rawConn, err := proxy.dialRawConn(ctx, "tcp", addr, fakeReq)
		if err != nil {
			return nil, err
		}
		freshTls, err := chromeTLSDial(ctx, rawConn, serverTlsConfig.Clone())
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		return freshTls, nil
	}

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	if serverTlsState.NegotiatedProtocol == "h2" {
		// Server negotiated h2: use http2.Transport directly.
		// For h2 clients serveConn will replace this transport (firstDial not
		// consumed yet so serverTlsConn stays fresh). For http/1.1 clients this
		// transport is used as-is — http.Transport cannot alt-proto-upgrade a
		// *chromeTLSConn so we must own the h2 framing ourselves.
		serverConn.client = &http.Client{
			Transport: &http2.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					dialMu.Lock()
					first := firstDial
					firstDial = false
					dialMu.Unlock()
					if first {
						return serverTlsConn, nil
					}
					return reconnectFn(ctx, addr)
				},
				DisableCompression:        true,
				MaxHeaderListSize:         262144,
				MaxDecoderHeaderTableSize: 65536,
			},
			CheckRedirect: checkRedirect,
		}
	} else {
		serverConn.client = &http.Client{
			Transport: &http.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialMu.Lock()
					first := firstDial
					firstDial = false
					dialMu.Unlock()
					if first {
						return serverTlsConn, nil
					}
					return reconnectFn(ctx, addr)
				},
				ForceAttemptHTTP2:  false,
				DisableCompression: true,
			},
			CheckRedirect: checkRedirect,
		}
	}

	return nil
}

func tlsServerName(connCtx *ConnContext, clientHelloServerName string) string {
	if clientHelloServerName != "" {
		return clientHelloServerName
	}
	if connCtx == nil || connCtx.ServerConn == nil {
		return ""
	}
	host := connCtx.ServerConn.Address
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func acceptsEventStream(header http.Header) bool {
	return strings.Contains(strings.ToLower(header.Get("Accept")), "text/event-stream")
}

func isJSONRequest(header http.Header) bool {
	ct := strings.ToLower(header.Get("Content-Type"))
	if i := strings.Index(ct, ";"); i != -1 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}

func topLevelJSONBool(body []byte, key string) (bool, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return false, false
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return false, false
	}
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return false, false
		}
		name, ok := tok.(string)
		if !ok {
			return false, false
		}
		if name == key {
			var value bool
			if err := dec.Decode(&value); err != nil {
				return false, false
			}
			return value, true
		}
		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			return false, false
		}
	}
	return false, false
}

func wantsStreamingResponse(header http.Header, body []byte) bool {
	if acceptsEventStream(header) {
		return true
	}
	if len(body) == 0 || !isJSONRequest(header) {
		return false
	}
	stream, ok := topLevelJSONBool(body, "stream")
	return ok && stream
}

func forceIdentityEncoding(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Del("Accept-Encoding")
	req.Header.Set("Accept-Encoding", "identity")
}

func responseHopByHopHeaders(header http.Header) map[string]struct{} {
	headers := map[string]struct{}{
		"Connection":          {},
		"Keep-Alive":          {},
		"Proxy-Authenticate":  {},
		"Proxy-Authorization": {},
		"Proxy-Connection":    {},
		"Te":                  {},
		"Trailer":             {},
		"Transfer-Encoding":   {},
		"Upgrade":             {},
	}
	for _, connectionHeader := range header.Values("Connection") {
		for _, token := range strings.Split(connectionHeader, ",") {
			if token = strings.TrimSpace(token); token != "" {
				headers[http.CanonicalHeaderKey(token)] = struct{}{}
			}
		}
	}
	return headers
}

func copyResponseHeaders(dst, src http.Header, streamingBody bool) {
	if src == nil {
		return
	}
	skip := responseHopByHopHeaders(src)
	if streamingBody {
		// Streaming filters can transform response bytes (for example gzip SSE
		// decoding), so any upstream Content-Length is no longer authoritative.
		skip["Content-Length"] = struct{}{}
	}
	for key, value := range src {
		if _, ok := skip[http.CanonicalHeaderKey(key)]; ok {
			continue
		}
		for _, v := range value {
			dst.Add(key, v)
		}
	}
}

func isEventStreamHeader(header http.Header) bool {
	return strings.Contains(strings.ToLower(header.Get("Content-Type")), "text/event-stream")
}

func lastSSEEventBoundary(buf []byte) int {
	last := -1
	lastLen := 0
	for _, sep := range [][]byte{
		[]byte("\n\n"),
		[]byte("\r\n\r\n"),
		[]byte("\r\r"),
		[]byte("\n\r\n"),
		[]byte("\r\n\n"),
	} {
		if idx := bytes.LastIndex(buf, sep); idx >= 0 && idx+len(sep) > last+lastLen {
			last = idx
			lastLen = len(sep)
		}
	}
	if last < 0 {
		return -1
	}
	return last + lastLen
}

const rawSSEHeartbeatInterval = time.Second

var rawSSEHeartbeat = []byte(":\n\n")

func updateSSETail(tail, chunk []byte) []byte {
	const maxBoundaryLen = len("\r\n\r\n")
	if len(chunk) == 0 {
		return tail
	}
	if len(chunk) >= maxBoundaryLen {
		out := make([]byte, maxBoundaryLen)
		copy(out, chunk[len(chunk)-maxBoundaryLen:])
		return out
	}
	combined := make([]byte, 0, len(tail)+len(chunk))
	combined = append(combined, tail...)
	combined = append(combined, chunk...)
	if len(combined) > maxBoundaryLen {
		combined = combined[len(combined)-maxBoundaryLen:]
	}
	return combined
}

func endsAtSSEEventBoundary(tail []byte) bool {
	return len(tail) == 0 || lastSSEEventBoundary(tail) == len(tail)
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

func makeProxyRequest(ctx context.Context, f *Flow, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, f.Request.Method, f.Request.URL.String(), body)
	if err != nil {
		return nil, err
	}
	for key, value := range f.Request.Header {
		for _, v := range value {
			req.Header.Add(key, v)
		}
	}
	return req, nil
}

func canReplayRequest(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func (a *attacker) initHttpsDialFn(req *http.Request) {
	connCtx := req.Context().Value(connContextKey).(*ConnContext)

	connCtx.dialFn = func(ctx context.Context) error {
		_, err := a.httpsDial(ctx, req)
		if err != nil {
			return err
		}
		if err := a.serverTlsHandshake(ctx, connCtx); err != nil {
			return err
		}
		return nil
	}
}

func (a *attacker) httpsDial(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxy := a.proxy
	connCtx := req.Context().Value(connContextKey).(*ConnContext)

	plainConn, err := proxy.getUpstreamConn(ctx, req)
	if err != nil {
		return nil, err
	}

	serverConn := newServerConn()
	serverConn.Address = req.Host
	serverConn.Conn = &wrapServerConn{
		Conn:    plainConn,
		proxy:   proxy,
		connCtx: connCtx,
	}
	connCtx.ServerConn = serverConn
	for _, addon := range connCtx.proxy.Addons {
		addon.ServerConnected(connCtx)
	}

	return serverConn.Conn, nil
}

func (a *attacker) httpsTlsDial(ctx context.Context, cconn net.Conn, conn net.Conn) {
	connCtx := cconn.(*wrapClientConn).connCtx
	log := log.WithFields(log.Fields{
		"in":   "Proxy.attacker.httpsTlsDial",
		"host": connCtx.ClientConn.Conn.RemoteAddr().String(),
	})

	var clientHello *tls.ClientHelloInfo
	clientHelloChan := make(chan *tls.ClientHelloInfo)
	serverTlsStateChan := make(chan *tls.ConnectionState)
	errChan1 := make(chan error, 1)
	errChan2 := make(chan error, 1)
	clientHandshakeDoneChan := make(chan struct{})

	// Chrome/Firefox send TLS 1.3 early data (0-RTT) when they have a cached
	// session ticket from a previous proxy session. Go's crypto/tls hard-rejects
	// this for non-QUIC connections with no way to configure it. Strip the
	// early_data extension from the ClientHello bytes before Go sees them.
	clientTlsConn := tls.Server(stripEarlyData(cconn), &tls.Config{
		SessionTicketsDisabled: true, // 设置此值为 true ，确保每次都会调用下面的 GetConfigForClient 方法
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHelloChan <- chi
			nextProtos := make([]string, 0)

			// wait server handshake finish
			select {
			case err := <-errChan2:
				return nil, err
			case serverTlsState := <-serverTlsStateChan:
				if serverTlsState.NegotiatedProtocol != "" {
					nextProtos = append([]string{serverTlsState.NegotiatedProtocol}, nextProtos...)
				}
			}

			certName := tlsServerName(connCtx, chi.ServerName)
			if certName == "" {
				certName = chi.ServerName
			}
			c, err := a.ca.GetCert(certName)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				SessionTicketsDisabled: true,
				Certificates:           []tls.Certificate{*c},
				NextProtos:             nextProtos,
			}, nil

		},
	})
	go func() {
		if err := clientTlsConn.HandshakeContext(ctx); err != nil {
			errChan1 <- err
			return
		}
		close(clientHandshakeDoneChan)
	}()

	// get clientHello from client
	select {
	case err := <-errChan1:
		cconn.Close()
		conn.Close()
		log.Error(err)
		return
	case clientHello = <-clientHelloChan:
	}
	connCtx.ClientConn.clientHello = clientHello

	if err := a.serverTlsHandshake(ctx, connCtx); err != nil {
		cconn.Close()
		conn.Close()
		errChan2 <- err
		log.Error(err)
		return
	}
	serverTlsStateChan <- connCtx.ServerConn.tlsState

	// wait client handshake finish
	select {
	case err := <-errChan1:
		cconn.Close()
		conn.Close()
		// Browser closed the connection before finishing the TLS handshake —
		// normal when Chrome abandons a speculative pre-connection.
		logErr(log, err)
		return
	case <-clientHandshakeDoneChan:
	}

	// will go to attacker.ServeHTTP
	a.serveConn(clientTlsConn, connCtx)
}

func (a *attacker) httpsLazyAttack(ctx context.Context, cconn net.Conn, req *http.Request) {
	connCtx := cconn.(*wrapClientConn).connCtx
	log := log.WithFields(log.Fields{
		"in":   "Proxy.attacker.httpsLazyAttack",
		"host": connCtx.ClientConn.Conn.RemoteAddr().String(),
	})

	clientTlsConn := tls.Server(stripEarlyData(cconn), &tls.Config{
		SessionTicketsDisabled: true, // 设置此值为 true ，确保每次都会调用下面的 GetConfigForClient 方法
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			connCtx.ClientConn.clientHello = chi
			certName := tlsServerName(connCtx, chi.ServerName)
			if certName == "" {
				certName = chi.ServerName
			}
			c, err := a.ca.GetCert(certName)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				SessionTicketsDisabled: true,
				Certificates:           []tls.Certificate{*c},
				NextProtos:             []string{"h2", "http/1.1"},
			}, nil
		},
	})
	if err := clientTlsConn.HandshakeContext(ctx); err != nil {
		cconn.Close()
		logErr(log, err)
		return
	}

	// For H1.1 clients: set up the legacy server-side dial function (dial on
	// first request, reuse the established TLS conn for subsequent ones).
	// For H2 clients: serveConn installs a clean H1.1 upstream dial that
	// avoids H2 GOAWAY killing SSE streams — no pre-dial needed.
	if clientTlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		a.initHttpsDialFn(req)
	}

	a.serveConn(clientTlsConn, connCtx)
}

func (a *attacker) attack(res http.ResponseWriter, req *http.Request) {
	proxy := a.proxy

	log := log.WithFields(log.Fields{
		"in":     "Proxy.attacker.attack",
		"url":    req.URL,
		"method": req.Method,
	})

	reply := func(response *Response, body io.Reader) {
		streamingBody := body != nil || response.BodyReader != nil
		copyResponseHeaders(res.Header(), response.Header, streamingBody)
		if response.close && req.ProtoMajor < 2 {
			res.Header().Set("Connection", "close")
		}
		isEventStream := isEventStreamHeader(response.Header)
		eventStream := isEventStream && !proxy.Opts.RawSSEPassthrough
		rawSSEPassthrough := isEventStream && proxy.Opts.RawSSEPassthrough
		if eventStream {
			log.Debugf("using SSE event-boundary downstream flush for %s", req.URL.String())
		}
		if rawSSEPassthrough {
			log.Debugf("using SSE raw downstream heartbeat for %s", req.URL.String())
		}
		res.WriteHeader(response.StatusCode)

		flusher, _ := res.(http.Flusher)
		// flushFn flushes the response writer and returns any error.
		// x/net/http2's ResponseWriter implements FlushError() which surfaces
		// stream-closed errors immediately; plain http.Flusher silently discards them.
		type flusherErr interface{ FlushError() error }
		flushFn := func() error {
			if fe, ok := res.(flusherErr); ok {
				return fe.FlushError()
			}
			if flusher != nil {
				flusher.Flush()
			}
			return nil
		}
		// Send the H2 HEADERS frame to the client immediately.  Without this
		// flush, x/net/http2 delays the HEADERS frame until the first Write()
		// call.  For SSE streams the first Write() may come 1+ seconds later
		// (inspection window), by which time the client (e.g. Claude.exe) has
		// already timed out waiting for any HTTP response.
		if flusher != nil {
			if err := flushFn(); err != nil {
				log.Debugf("reply: initial header flush failed (client gone): %v", err)
				return
			}
		}

		writeAndFlush := func(p []byte) error {
			if len(p) == 0 {
				return nil
			}
			if _, werr := res.Write(p); werr != nil {
				if isStreamEnd(werr) {
					log.Debugf("copyStream: client write ended: %v", werr)
				} else {
					log.Warnf("copyStream: client write failed: %v", werr)
				}
				return werr
			}
			if werr := flushFn(); werr != nil {
				if isStreamEnd(werr) {
					log.Debugf("copyStream: flush ended: %v", werr)
				} else {
					log.Warnf("copyStream: flush failed: %v", werr)
				}
				return werr
			}
			return nil
		}

		copyStream := func(r io.Reader) error {
			if r == nil {
				return nil
			}
			if rawSSEPassthrough {
				type readResult struct {
					data []byte
					err  error
				}
				readCh := make(chan readResult, 1)
				readNext := func() {
					go func() {
						buf := make([]byte, 32*1024)
						n, err := r.Read(buf)
						if n > 0 {
							buf = buf[:n]
						} else {
							buf = nil
						}
						readCh <- readResult{data: buf, err: err}
					}()
				}

				heartbeat := time.NewTimer(rawSSEHeartbeatInterval)
				defer heartbeat.Stop()
				sseTail := []byte(nil)

				readNext()
				for {
					select {
					case result := <-readCh:
						if len(result.data) > 0 {
							if err := writeAndFlush(result.data); err != nil {
								return err
							}
							sseTail = updateSSETail(sseTail, result.data)
							resetTimer(heartbeat, rawSSEHeartbeatInterval)
						}
						if result.err != nil {
							if result.err == io.EOF || isStreamEnd(result.err) {
								return nil
							}
							log.Warnf("copyStream: upstream read failed: %v", result.err)
							return result.err
						}
						readNext()

					case <-heartbeat.C:
						if endsAtSSEEventBoundary(sseTail) {
							if err := writeAndFlush(rawSSEHeartbeat); err != nil {
								return err
							}
							sseTail = updateSSETail(sseTail, rawSSEHeartbeat)
						}
						heartbeat.Reset(rawSSEHeartbeatInterval)
					}
				}
			}

			buf := make([]byte, 32*1024)
			var pending []byte
			const maxPendingSSEBytes = 1024 * 1024

			flushSSE := func(force bool) error {
				if len(pending) == 0 {
					return nil
				}
				cut := lastSSEEventBoundary(pending)
				if force {
					cut = len(pending)
				} else if cut < 0 {
					if len(pending) < maxPendingSSEBytes {
						return nil
					}
					// Malformed or extremely large event: flush rather than let
					// one response consume unbounded memory.
					cut = len(pending)
				}
				if err := writeAndFlush(pending[:cut]); err != nil {
					return err
				}
				copy(pending, pending[cut:])
				pending = pending[:len(pending)-cut]
				return nil
			}

			for {
				n, err := r.Read(buf)
				if n > 0 {
					if eventStream {
						pending = append(pending, buf[:n]...)
						if werr := flushSSE(false); werr != nil {
							return werr
						}
					} else {
						if werr := writeAndFlush(buf[:n]); werr != nil {
							return werr
						}
					}
				}
				if err != nil {
					if err == io.EOF || isStreamEnd(err) {
						if eventStream {
							return flushSSE(true)
						}
						return nil
					}
					log.Warnf("copyStream: upstream read failed: %v", err)
					return err
				}
			}
		}

		if body != nil {
			err := copyStream(body)
			if err != nil {
				logErr(log, err)
			}
		}
		if response.BodyReader != nil {
			err := copyStream(response.BodyReader)
			if err != nil {
				logErr(log, err)
			}
		}
		if len(response.Body) > 0 {
			_, err := res.Write(response.Body)
			if err != nil {
				logErr(log, err)
			}
		}
	}

	// when addons panic
	defer func() {
		if err := recover(); err != nil {
			log.Warnf("Recovered: %v\n", err)
		}
	}()

	f := newFlow()
	f.Request = newRequest(req)
	f.ConnContext = req.Context().Value(connContextKey).(*ConnContext)
	defer f.finish()

	f.ConnContext.FlowCount.Add(1)

	rawReqUrlHost := f.Request.URL.Host
	rawReqUrlScheme := f.Request.URL.Scheme

	// trigger addon event Requestheaders
	for _, addon := range proxy.Addons {
		addon.Requestheaders(f)
		if f.Response != nil {
			reply(f.Response, nil)
			return
		}
	}

	// Read request body
	var reqBody io.Reader = req.Body
	if !f.Stream {
		reqBuf, r, err := helper.ReaderToBuffer(req.Body, proxy.Opts.StreamLargeBodies)
		reqBody = r
		if err != nil {
			for _, addon := range proxy.Addons {
				addon.RequestError(f, err)
			}
			res.WriteHeader(502)
			return
		}

		if reqBuf == nil {
			log.Warnf("request body size >= %v\n", proxy.Opts.StreamLargeBodies)
			f.Stream = true
		} else {
			f.Request.Body = reqBuf

			// trigger addon event Request
			for _, addon := range proxy.Addons {
				addon.Request(f)
				if f.Response != nil {
					reply(f.Response, nil)
					return
				}
			}
			reqBody = bytes.NewReader(f.Request.Body)
		}
	}

	for _, addon := range proxy.Addons {
		reqBody = addon.StreamRequestModifier(f, reqBody)
	}

	// Upstream context is intentionally NOT tied to the h2 stream context.
	// A client RST_STREAM (e.g. Cursor canceling the stream while we're
	// dialing or reading the upstream response) must not abort an in-flight
	// request: the transport reconnect and the response copy will clean up
	// naturally, and defer upstreamCancel ensures the upstream request is
	// released when attack() returns regardless.
	upstreamCtx, upstreamCancel := context.WithCancel(context.Background())
	defer upstreamCancel()
	proxyReqCtx := context.WithValue(upstreamCtx, proxyReqCtxKey, req)

	proxyReq, err := makeProxyRequest(proxyReqCtx, f, reqBody)
	if err != nil {
		for _, addon := range proxy.Addons {
			addon.RequestError(f, err)
		}
		res.WriteHeader(502)
		return
	}

	useSeparateClient := f.UseSeparateClient
	separateClient := a.client
	expectsStreamingResponse := wantsStreamingResponse(f.Request.Header, f.Request.Body)
	if expectsStreamingResponse {
		// Streaming responses cannot be safely resumed once bytes have been sent
		// to the client. Use a fresh H2-capable upstream connection with
		// keepalives disabled so the stream is isolated from shared-connection
		// GOAWAY while still letting servers negotiate HTTP/2 when supported.
		useSeparateClient = true
		separateClient = a.streamClient
		forceIdentityEncoding(proxyReq)
		log.Debugf("using isolated upstream client for streaming response request %s acceptEncoding=%s", f.Request.URL.String(), proxyReq.Header.Get("Accept-Encoding"))
	}
	if !useSeparateClient {
		if rawReqUrlHost != f.Request.URL.Host || rawReqUrlScheme != f.Request.URL.Scheme {
			useSeparateClient = true
		}
	}

	var proxyRes *http.Response
	if useSeparateClient {
		proxyRes, err = separateClient.Do(proxyReq)
	} else {
		if f.ConnContext.ServerConn == nil && f.ConnContext.dialFn != nil {
			if err := f.ConnContext.dialFn(req.Context()); err != nil {
				for _, addon := range proxy.Addons {
					addon.RequestError(f, err)
				}
				// Check for authentication failure
				if strings.Contains(err.Error(), "Proxy Authentication Required") {
					httpError(res, "", http.StatusProxyAuthRequired)
					return
				}
				res.WriteHeader(502)
				return
			}
		}
		proxyRes, err = f.ConnContext.ServerConn.client.Do(proxyReq)
		// GOAWAY retry: the H2 upstream rotated its connection while our
		// request was in-flight.  f.Request.Body is already buffered as []byte
		// so we can re-issue on the fresh connection the transport opens.
		// f.Stream (SSE) is intentionally included: a GOAWAY before the first
		// response byte is safe to retry without duplicating downstream data.
		if err != nil && f.Request.Body != nil && canReplayRequest(f.Request.Method) &&
			strings.Contains(err.Error(), "GOAWAY") {
			log.Infof("GOAWAY on upstream Do(), retrying: %v", err)
			retryReq, e2 := http.NewRequestWithContext(proxyReqCtx, f.Request.Method, f.Request.URL.String(), bytes.NewReader(f.Request.Body))
			if e2 == nil {
				for key, value := range f.Request.Header {
					for _, v := range value {
						retryReq.Header.Add(key, v)
					}
				}
				proxyRes, err = f.ConnContext.ServerConn.client.Do(retryReq)
			}
		}
	}
	if err != nil {
		logErr(log, err)
		for _, addon := range proxy.Addons {
			addon.RequestError(f, err)
		}
		res.WriteHeader(502)
		return
	}

	if proxyRes.Close {
		f.ConnContext.closeAfterResponse = true
	}

	defer proxyRes.Body.Close()

	f.Response = &Response{
		StatusCode: proxyRes.StatusCode,
		Header:     proxyRes.Header,
		close:      proxyRes.Close,
	}

	// trigger addon event Responseheaders
	for _, addon := range proxy.Addons {
		addon.Responseheaders(f)
		if f.Response.Body != nil {
			reply(f.Response, nil)
			return
		}
	}

	// 检测是否为 SSE 响应，如果是则强制使用流式模式
	isSSE := isEventStreamHeader(f.Response.Header)
	if isSSE {
		f.Stream = true
		if !proxy.Opts.RawSSEPassthrough {
			f.SSE = newSSEData()

			// 触发 SSEStart hook
			for _, addon := range proxy.Addons {
				addon.SSEStart(f)
			}
		} else {
			log.Debugf("SSE raw passthrough enabled for %s; generic SSE hooks disabled, stream modifiers still active", f.Request.URL.String())
		}

		log.Debugf("SSE stream detected for %s upstreamProto=%s status=%d contentEncoding=%q contentLength=%d", f.Request.URL.String(), proxyRes.Proto, proxyRes.StatusCode, proxyRes.Header.Get("Content-Encoding"), proxyRes.ContentLength)
	}

	// application/octet-stream is opaque binary data (e.g. React Server
	// Components from LinkedIn). Buffering it before forwarding causes
	// multi-second latency for large responses (8+ MB) which makes the
	// browser close the H2 stream before we can deliver the response.
	// Stream it directly — there is no meaningful content to inspect.
	if strings.HasPrefix(proxyRes.Header.Get("Content-Type"), "application/octet-stream") {
		f.Stream = true
	}

	// Read response body
	var resBody io.Reader = proxyRes.Body
	if !f.Stream {
		resBuf, r, err := helper.ReaderToBuffer(proxyRes.Body, proxy.Opts.StreamLargeBodies)
		resBody = r
		if err != nil {
			for _, addon := range proxy.Addons {
				addon.RequestError(f, err)
			}
			res.WriteHeader(502)
			return
		}
		if resBuf == nil {
			log.Warnf("response body size >= %v\n", proxy.Opts.StreamLargeBodies)
			f.Stream = true
		} else {
			f.Response.Body = resBuf

			// trigger addon event Response
			for _, addon := range proxy.Addons {
				addon.Response(f)
			}
		}
	}

	// 如果是 SSE，包装 reader 以实时解析事件
	if isSSE {
		reissueClient := a.client
		if useSeparateClient {
			reissueClient = separateClient
		} else if f.ConnContext.ServerConn != nil && f.ConnContext.ServerConn.client != nil {
			reissueClient = f.ConnContext.ServerConn.client
		}

		// Wrap with a GOAWAY-resilient reader before the SSE parser so that
		// a mid-stream upstream connection rotation is handled transparently:
		//   • If no bytes read yet → re-issue request on fresh connection (safe replay).
		//   • If bytes already read → return io.EOF so downstream gets a clean
		//     truncated response rather than ERR_CONNECTION_CLOSED.
		gb := &goawayBody{
			body:        proxyRes.Body,
			ctx:         proxyReqCtx,
			retriesLeft: maxGoawayRetries,
			reissue: func() (io.ReadCloser, error) {
				if !canReplayRequest(f.Request.Method) {
					return nil, io.EOF
				}
				if f.Request.Body == nil {
					return nil, io.EOF // un-buffered body; cannot replay
				}
				retryReq, e2 := http.NewRequestWithContext(proxyReqCtx, f.Request.Method, f.Request.URL.String(), bytes.NewReader(f.Request.Body))
				if e2 != nil {
					return nil, e2
				}
				for key, value := range f.Request.Header {
					for _, v := range value {
						retryReq.Header.Add(key, v)
					}
				}
				if expectsStreamingResponse {
					forceIdentityEncoding(retryReq)
				}
				r, e2 := reissueClient.Do(retryReq)
				if e2 != nil {
					return nil, e2
				}
				if r.StatusCode != proxyRes.StatusCode {
					r.Body.Close()
					return nil, io.EOF // unexpected status on retry; fall through to clean EOF
				}
				return r.Body, nil
			},
		}
		// gb.Close() closes whichever body is current (original or retry).
		// The existing defer proxyRes.Body.Close() still closes the original;
		// gb.Close() ensures the retry body is also released when attack() returns.
		defer gb.Close()
		resBody = gb
		if !proxy.Opts.RawSSEPassthrough {
			resBody = newSSEReader(f, resBody)
		}
	}

	for _, addon := range proxy.Addons {
		resBody = addon.StreamResponseModifier(f, resBody)
	}

	reply(f.Response, resBody)
}
