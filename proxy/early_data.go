package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// stripEarlyData wraps conn so that the first TLS ClientHello has the
// early_data extension (type 0x002a) removed before Go's crypto/tls sees it.
//
// Go's crypto/tls hard-rejects non-QUIC connections that advertise early data
// (TLS 1.3 0-RTT) with "tls: client sent unexpected early data" and closes the
// connection. There is no config knob to suppress this. Chrome and Firefox
// include early_data when they have a cached session ticket — even one from a
// previous MITM proxy session — so this rewrite is necessary to keep the
// handshake alive and allow interception.
//
// If reading or parsing fails for any reason the original bytes are replayed
// unchanged so we never break non-TLS or already-clean connections.
func stripEarlyData(conn net.Conn) net.Conn {
	// TLS record header is 5 bytes: type(1) + version(2) + length(2)
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return &prefixedConn{Conn: conn, buf: hdr}
	}

	// 0x16 = TLS handshake record
	if hdr[0] != 0x16 {
		return &prefixedConn{Conn: conn, buf: hdr}
	}

	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	rec := make([]byte, recLen)
	if _, err := io.ReadFull(conn, rec); err != nil {
		return &prefixedConn{Conn: conn, buf: append(hdr, rec...)}
	}

	// Handshake message: type(1) + length(3) + body
	// type 0x01 = ClientHello
	if len(rec) < 4 || rec[0] != 0x01 {
		return &prefixedConn{Conn: conn, buf: append(hdr, rec...)}
	}

	modified, changed := removeEarlyDataExt(rec[4:]) // body starts after 4-byte handshake header
	if !changed {
		return &prefixedConn{Conn: conn, buf: append(hdr, rec...)}
	}

	// Rebuild handshake message with updated length
	newBody := modified
	newHdr := make([]byte, 4)
	newHdr[0] = 0x01 // ClientHello
	newHdr[1] = byte(len(newBody) >> 16)
	newHdr[2] = byte(len(newBody) >> 8)
	newHdr[3] = byte(len(newBody))
	newMsg := append(newHdr, newBody...)

	// Rebuild TLS record header with updated length
	newRec := make([]byte, 5)
	copy(newRec, hdr[:3]) // type + version unchanged
	binary.BigEndian.PutUint16(newRec[3:], uint16(len(newMsg)))

	prefix := append(newRec, newMsg...)

	// Chrome sends 0-RTT early data records (type 0x17) immediately after the
	// ClientHello, before waiting for the server response. Stripping the
	// early_data extension from the ClientHello is not enough — Go's TLS server
	// will see those 0x17 records and fail with "bad record MAC" because it has
	// no early-data key. Drain all 0x17 records, keeping other records in prefix.
	//
	// Chrome's TLS 1.3 middlebox-compat mode inserts a CCS (0x14) record
	// BETWEEN the ClientHello and the early data:
	//   ClientHello → CCS(0x14) → early-data(0x17)...
	// The old code broke out of the loop on 0x14, leaving the 0x17 records
	// in the stream — Go's TLS would then see them and panic with "bad record MAC".
	// Fix: always read the full body of every record; pass 0x14 through to prefix
	// and continue the loop so trailing 0x17 records are still drained.
	//
	// IMPORTANT: io.ReadFull returns (n, err) where n may be > 0 even on error
	// (e.g. a deadline timeout mid-read). Any partially-read bytes MUST be
	// saved back to prefix; discarding them corrupts the TLS stream.
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	for {
		earlyHdr := make([]byte, 5)
		n, err := io.ReadFull(conn, earlyHdr)
		if err != nil {
			// Save any partial bytes so the TLS layer sees a complete stream.
			prefix = append(prefix, earlyHdr[:n]...)
			break
		}
		earlyLen := int(binary.BigEndian.Uint16(earlyHdr[3:5]))
		earlyBody := make([]byte, earlyLen)
		n, err = io.ReadFull(conn, earlyBody)
		if err != nil {
			// Couldn't read the full body; restore header + partial body.
			prefix = append(prefix, earlyHdr...)
			prefix = append(prefix, earlyBody[:n]...)
			break
		}
		if earlyHdr[0] == 0x17 {
			// 0-RTT application data — discard.
			continue
		}
		// Non-early-data record: always include the full record (header+body).
		// CCS (0x14) precedes early data in compat mode — keep it and continue
		// so we drain the 0x17 records that follow. Any other type ends the
		// early-data window.
		prefix = append(prefix, earlyHdr...)
		prefix = append(prefix, earlyBody...)
		if earlyHdr[0] != 0x14 {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{}) // clear deadline

	return &prefixedConn{Conn: conn, buf: prefix}
}

// removeEarlyDataExt removes the early_data extension (type 0x002a) from the
// ClientHello body (i.e. the bytes after the 4-byte handshake header).
// Returns the (possibly modified) body and whether any change was made.
func removeEarlyDataExt(body []byte) ([]byte, bool) {
	const earlyDataType = 0x002a

	offset := 0

	// client_version: 2 bytes
	if offset+2 > len(body) {
		return body, false
	}
	offset += 2

	// random: 32 bytes
	if offset+32 > len(body) {
		return body, false
	}
	offset += 32

	// session_id: 1-byte length + data
	if offset+1 > len(body) {
		return body, false
	}
	sidLen := int(body[offset])
	offset += 1 + sidLen

	// cipher_suites: 2-byte length + data
	if offset+2 > len(body) {
		return body, false
	}
	csLen := int(binary.BigEndian.Uint16(body[offset:]))
	offset += 2 + csLen

	// compression_methods: 1-byte length + data
	if offset+1 > len(body) {
		return body, false
	}
	cmLen := int(body[offset])
	offset += 1 + cmLen

	// extensions: 2-byte total length
	if offset+2 > len(body) {
		return body, false // no extensions
	}
	extTotalLen := int(binary.BigEndian.Uint16(body[offset:]))
	extLenOffset := offset
	offset += 2
	extStart := offset
	extEnd := extStart + extTotalLen
	if extEnd > len(body) {
		return body, false
	}

	// Walk extensions, collect all except early_data
	var kept bytes.Buffer
	pos := extStart
	found := false
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[pos:])
		extLen := int(binary.BigEndian.Uint16(body[pos+2:]))
		extFull := pos + 4 + extLen
		if extFull > extEnd {
			break
		}
		if extType == earlyDataType {
			found = true
		} else {
			kept.Write(body[pos:extFull])
		}
		pos = extFull
	}

	if !found {
		return body, false
	}

	// Rebuild body: everything before extension length field + new exts + tail
	newBody := make([]byte, 0, len(body))
	newBody = append(newBody, body[:extLenOffset]...)
	newExts := kept.Bytes()
	newBody = append(newBody, byte(len(newExts)>>8), byte(len(newExts)))
	newBody = append(newBody, newExts...)
	newBody = append(newBody, body[extEnd:]...) // any trailing data after extensions
	return newBody, true
}

// prefixedConn replays buffered bytes before delegating to the underlying conn.
type prefixedConn struct {
	net.Conn
	buf []byte
	off int
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	if c.off < len(c.buf) {
		n := copy(b, c.buf[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(b)
}
