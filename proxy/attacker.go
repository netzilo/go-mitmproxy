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
				Proxy:              proxy.realUpstreamProxy(),
				ForceAttemptHTTP2:  true,
				DisableCompression: true, // To get the original response from the server, set Transport.DisableCompression to true.
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
		if connCtx.ServerConn != nil {
			// First-dial path (UpstreamCert mode): a real TLS connection to the
			// server was established before the client handshake.  Use a bare
			// http2.Transport so we get H2 multiplexing upstream, and install a
			// DialTLSContext that re-dials a fresh connection after GOAWAY.
			var dialMu sync.Mutex
			firstDial := true
			connCtx.ServerConn.client = &http.Client{
				Transport: &http2.Transport{
					DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
						dialMu.Lock()
						first := firstDial
						firstDial = false
						dialMu.Unlock()

						if first {
							return connCtx.ServerConn.tlsConn, nil
						}

						fakeReq := &http.Request{URL: &url.URL{Scheme: "https", Host: addr}}
						proxyURL, err := a.proxy.getUpstreamProxyUrl(fakeReq)
						if err != nil {
							return nil, err
						}
						var rawConn net.Conn
						if proxyURL != nil {
							rawConn, err = helper.GetProxyConn(ctx, proxyURL, addr, a.proxy.Opts.SslInsecure)
						} else {
							rawConn, err = (&net.Dialer{}).DialContext(ctx, network, addr)
						}
						if err != nil {
							return nil, err
						}
						tlsConn := tls.Client(rawConn, cfg)
						if err := tlsConn.HandshakeContext(ctx); err != nil {
							rawConn.Close()
							return nil, err
						}
						return tlsConn, nil
					},
					DisableCompression: true,
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		} else {
			// Lazy path: the client negotiated H2 with our proxy but no server
			// connection has been pre-established.  Use H2 upstream so that the
			// server sends response HEADERS immediately (before model generation
			// starts), giving the downstream client its 200 OK early.
			//
			// GOAWAY is handled by retrying in attack() using the buffered request
			// body (f.Request.Body []byte).
			sni := connCtx.ClientConn.clientHello.ServerName
			proxy := a.proxy
			connCtx.dialFn = func(ctx context.Context) error {
				serverConn := newServerConn()
				serverConn.Address = sni
				serverConn.client = &http.Client{
					Transport: &http2.Transport{
						DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
							fakeReq := &http.Request{URL: &url.URL{Scheme: "https", Host: addr}}
							proxyURL, err := proxy.getUpstreamProxyUrl(fakeReq)
							if err != nil {
								return nil, err
							}
							var rawConn net.Conn
							if proxyURL != nil {
								rawConn, err = helper.GetProxyConn(ctx, proxyURL, addr, proxy.Opts.SslInsecure)
							} else {
								rawConn, err = (&net.Dialer{}).DialContext(ctx, network, addr)
							}
							if err != nil {
								return nil, err
							}
							tlsConn := tls.Client(rawConn, cfg)
							if err := tlsConn.HandshakeContext(ctx); err != nil {
								rawConn.Close()
								return nil, err
							}
							return tlsConn, nil
						},
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: proxy.Opts.SslInsecure,
							KeyLogWriter:       helper.GetTlsKeyLogWriter(),
						},
						DisableCompression: true,
					},
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
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

		ctx := context.WithValue(context.Background(), connContextKey, connCtx)
		ctx, cancel := context.WithCancel(ctx)
		go func() {
			<-connCtx.ClientConn.Conn.(*wrapClientConn).closeChan
			cancel()
		}()
		go func() {
			a.h2Server.ServeConn(clientTlsConn, &http2.ServeConnOpts{
				Context:    ctx,
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

	serverTlsConfig := &tls.Config{
		InsecureSkipVerify: proxy.Opts.SslInsecure,
		KeyLogWriter:       helper.GetTlsKeyLogWriter(),
		ServerName:         clientHello.ServerName,
		NextProtos:         clientHello.SupportedProtos,
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
	serverTlsConn := tls.Client(serverConn.Conn, serverTlsConfig)
	serverConn.tlsConn = serverTlsConn
	if err := serverTlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	serverTlsState := serverTlsConn.ConnectionState()
	serverConn.tlsState = &serverTlsState
	for _, addon := range proxy.Addons {
		addon.TlsEstablishedServer(connCtx)
	}

	serverConn.client = &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return serverTlsConn, nil
			},
			ForceAttemptHTTP2:  true,
			DisableCompression: true, // To get the original response from the server, set Transport.DisableCompression to true.
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 禁止自动重定向
			return http.ErrUseLastResponse
		},
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

	clientTlsConn := tls.Server(cconn, &tls.Config{
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

	clientTlsConn := tls.Server(cconn, &tls.Config{
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
		// Send the H2 HEADERS frame to the client immediately.  Without this
		// flush, x/net/http2 delays the HEADERS frame until the first Write()
		// call.  For SSE streams the first Write() may come 1+ seconds later
		// (inspection window), by which time the client (e.g. Claude.exe) has
		// already timed out waiting for any HTTP response.
		if flusher != nil {
			flusher.Flush()
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
					flusher.Flush()
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

	upstreamCtx, upstreamCancel := context.WithCancel(context.Background())
	defer upstreamCancel()
	go func() {
		select {
		case <-req.Context().Done():
			upstreamCancel()
		case <-upstreamCtx.Done():
		}
	}()
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
