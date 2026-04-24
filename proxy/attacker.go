package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
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
	proxy    *Proxy
	ca       cert.CA
	server   *http.Server
	h2Server *http2.Server
	client   *http.Client
	listener *attackerListener
}

func newAttacker(proxy *Proxy) (*attacker, error) {
	ca, err := newCa(proxy.Opts)
	if err != nil {
		return nil, err
	}

	a := &attacker{
		proxy: proxy,
		ca:    ca,
		client: &http.Client{
			Transport: &http.Transport{
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
				ForceAttemptHTTP2:  true,
				DisableCompression: true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: proxy.Opts.SslInsecure,
					KeyLogWriter:       helper.GetTlsKeyLogWriter(),
				},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// 禁止自动重定向
				return http.ErrUseLastResponse
			},
		},
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
			sni := connCtx.ClientConn.clientHello.ServerName
			proxy := a.proxy

			// Pre-dial: TCP+TLS in background using the session context so
			// individual stream cancellations don't abort the connection.
			type preDialResult struct {
				conn net.Conn
				err  error
			}
			preDialCh := make(chan preDialResult, 1)
			go func() {
				addr := sni + ":443"
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
		ServerName:         clientHello.ServerName,
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

			c, err := a.ca.GetCert(chi.ServerName)
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
		log.Error(err)
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
			c, err := a.ca.GetCert(chi.ServerName)
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
		log.Error(err)
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
		if response.Header != nil {
			for key, value := range response.Header {
				for _, v := range value {
					res.Header().Add(key, v)
				}
			}
		}
		if response.close {
			res.Header().Set("Connection", "close")
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
				log.Warnf("reply: initial header flush failed (stream closed): %v", err)
				return
			}
		}

		copyStream := func(r io.Reader) error {
			if r == nil {
				return nil
			}

			buf := make([]byte, 32*1024)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					if _, werr := res.Write(buf[:n]); werr != nil {
						log.Warnf("copyStream: client write failed: %v", werr)
						return werr
					}
					if werr := flushFn(); werr != nil {
						log.Warnf("copyStream: flush failed: %v", werr)
						return werr
					}
				}
				if err != nil {
					if err == io.EOF {
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
	proxyReq, err := http.NewRequestWithContext(proxyReqCtx, f.Request.Method, f.Request.URL.String(), reqBody)
	if err != nil {
		for _, addon := range proxy.Addons {
			addon.RequestError(f, err)
		}
		res.WriteHeader(502)
		return
	}

	for key, value := range f.Request.Header {
		for _, v := range value {
			proxyReq.Header.Add(key, v)
		}
	}

	useSeparateClient := f.UseSeparateClient
	if !useSeparateClient {
		if rawReqUrlHost != f.Request.URL.Host || rawReqUrlScheme != f.Request.URL.Scheme {
			useSeparateClient = true
		}
	}

	var proxyRes *http.Response
	if useSeparateClient {
		proxyRes, err = a.client.Do(proxyReq)
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
		if err != nil && !f.Stream && f.Request.Body != nil &&
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
	isSSE := strings.Contains(f.Response.Header.Get("Content-Type"), "text/event-stream")
	if isSSE {
		f.Stream = true
		f.SSE = newSSEData()

		// 触发 SSEStart hook
		for _, addon := range proxy.Addons {
			addon.SSEStart(f)
		}

		log.Debugf("SSE stream detected for %s", f.Request.URL.String())
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
		resBody = newSSEReader(f, resBody)
	}

	for _, addon := range proxy.Addons {
		resBody = addon.StreamResponseModifier(f, resBody)
	}

	reply(f.Response, resBody)
}
