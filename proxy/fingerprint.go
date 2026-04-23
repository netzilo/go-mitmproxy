package proxy

import (
	"context"
	"crypto/tls"
	"net"

	utls "github.com/refraction-networking/utls"
)

// chromeTLSConn wraps *utls.UConn and overrides ConnectionState() to return
// crypto/tls.ConnectionState instead of utls.ConnectionState. This is required
// because http.Transport and http2.Transport both use the interface
//
//	interface { ConnectionState() tls.ConnectionState }
//
// to read the negotiated ALPN protocol and decide whether to use HTTP/2.
// utls.UConn.ConnectionState() returns utls.ConnectionState (a different type),
// so without this wrapper the transports cannot detect h2 from our TLS conn.
type chromeTLSConn struct {
	*utls.UConn
}

func (c *chromeTLSConn) ConnectionState() tls.ConnectionState {
	us := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     us.Version,
		HandshakeComplete:           us.HandshakeComplete,
		DidResume:                   us.DidResume,
		CipherSuite:                 us.CipherSuite,
		NegotiatedProtocol:          us.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  us.NegotiatedProtocolIsMutual,
		ServerName:                  us.ServerName,
		PeerCertificates:            us.PeerCertificates,
		VerifiedChains:              us.VerifiedChains,
		SignedCertificateTimestamps: us.SignedCertificateTimestamps,
		OCSPResponse:                us.OCSPResponse,
		TLSUnique:                   us.TLSUnique,
	}
}

// chromeTLSDial performs a TLS handshake that impersonates Chrome 133's ClientHello
// (JA3/JA4 fingerprint). SNI, InsecureSkipVerify, NextProtos, and KeyLogWriter are
// taken from cfg. CipherSuites and TLS version constraints are intentionally ignored
// — Chrome's fixed spec replaces them, which is the correct trade-off for
// bot-detection bypass.
//
// ALPN override: HelloChrome_133's spec contains a hardcoded ALPNExtension that
// overwrites Config.NextProtos. We patch the spec's ALPN with cfg.NextProtos before
// applying it, so protocol filtering (e.g. removing h2 for HTTP/1.1 clients) is
// respected even when using the Chrome fingerprint.
func chromeTLSDial(ctx context.Context, rawConn net.Conn, cfg *tls.Config) (*chromeTLSConn, error) {
	utlsCfg := &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		NextProtos:         cfg.NextProtos,
		KeyLogWriter:       cfg.KeyLogWriter,
	}

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return nil, err
	}
	// Patch the spec's hardcoded ALPN extension with cfg.NextProtos.
	// Chrome_133 has a fixed ALPNExtension that ignores Config.NextProtos;
	// we must replace it so protocol filtering is respected.
	//
	// When cfg.NextProtos is empty (original client sent no ALPN), fall back
	// to ["http/1.1"]. This matches the original tls.Client behaviour — no
	// protocol negotiated → forceH2=false → http.Transport stays HTTP/1.1.
	// Without this, Chrome spec would offer h2, the server would negotiate it,
	// and http.Transport would fail to alt-proto-upgrade via our wrapper.
	nextProtos := cfg.NextProtos
	if len(nextProtos) == 0 {
		nextProtos = []string{"http/1.1"}
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = nextProtos
			break
		}
	}

	uConn := utls.UClient(rawConn, utlsCfg, utls.HelloCustom)
	if err := uConn.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return &chromeTLSConn{uConn}, nil
}
