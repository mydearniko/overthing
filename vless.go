package tunnel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/crypto/hkdf"

	utls "github.com/refraction-networking/utls"
)

// VLESSDialer dials destinations through a VLESS server protected by REALITY.
// The wire looks like an ordinary TLS 1.3 session (Chrome fingerprint) to the
// SNI host; the VLESS request and the inner traffic are invisible.
//
//   - server:  host:port of the VLESS/REALITY endpoint
//   - uuid:    VLESS user UUID
//   - sni:     ServerName presented (must be in the server's ServerNames list)
//   - pubKey:  REALITY public key (base64 raw URL encoding, 32 bytes)
//   - shortID: REALITY short ID (hex, up to 8 bytes)
type VLESSDialer struct {
	Server  string
	UUID    string
	SNI     string
	PubKey  string
	ShortID string
	Inner   DialerFunc // dialer used to reach Server itself (interface binding)
	Timeout time.Duration
}

// DialContext dials addr (host:port) THROUGH the VLESS server. Used as
// ServerConfig.Dialer so that relay connections ride inside the tunnel.
func (v *VLESSDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("vless: unsupported network %q", network)
	}
	timeout := v.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var conn net.Conn
	var err error
	if v.Inner != nil {
		conn, err = v.Inner(dialCtx, "tcp", v.Server)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(dialCtx, "tcp", v.Server)
	}
	if err != nil {
		return nil, fmt.Errorf("vless: dial server: %w", err)
	}

	tlsConn, err := v.realityHandshake(dialCtx, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := v.writeVLESSHead(tlsConn, addr); err != nil {
		tlsConn.Close()
		return nil, err
	}
	return &vlessRespConn{Conn: tlsConn}, nil
}

// realityHandshake performs the REALITY-authenticated TLS 1.3 handshake with
// a Chrome uTLS fingerprint. The server presents the SNI host's real
// certificate; authenticity is proven via an HMAC over the Ed25519 public key
// carried in the certificate's signature field.
func (v *VLESSDialer) realityHandshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	pubKey, err := base64.RawURLEncoding.DecodeString(v.PubKey)
	if err != nil || len(pubKey) != 32 {
		return nil, fmt.Errorf("vless: invalid reality public key")
	}
	var shortID [8]byte
	n, err := hex.Decode(shortID[:], []byte(v.ShortID))
	if err != nil || n > 8 {
		return nil, fmt.Errorf("vless: invalid reality short id")
	}

	verifier := &realityVerifier{serverName: v.SNI}
	uConfig := &utls.Config{
		ServerName:             v.SNI,
		NextProtos:             []string{"h2", "http/1.1"},
		InsecureSkipVerify:     true, // REALITY: verification is the HMAC below
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  verifier.VerifyPeerCertificate,
	}
	uConn := utls.UClient(conn, uConfig, utls.HelloChrome_Auto)
	verifier.UConn = uConn

	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("vless: build hello: %w", err)
	}
	// REALITY servers reject ML-KEM key shares (auth requires the X25519 share).
	for _, extension := range uConn.Extensions {
		if ce, ok := extension.(*utls.SupportedCurvesExtension); ok {
			ce.Curves = filterCurves(ce.Curves, utls.X25519MLKEM768)
		}
		if ks, ok := extension.(*utls.KeyShareExtension); ok {
			ks.KeyShares = filterShares(ks.KeyShares, utls.X25519MLKEM768)
		}
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("vless: rebuild hello: %w", err)
	}

	// Craft the REALITY session ID: [0]=1, [1]=8, [2]=1, [4:8]=unix time,
	// [8:16]=shortID, then Seal(sessionId[:16]) with HKDF(ECDH) and copy back.
	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	binary.BigEndian.PutUint64(hello.SessionId, uint64(time.Now().Unix()))
	hello.SessionId[0] = 1
	hello.SessionId[1] = 8
	hello.SessionId[2] = 1
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], shortID[:])

	realPub, err := ecdh.X25519().NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("vless: reality pubkey: %w", err)
	}
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil || keyShareKeys.Ecdhe == nil {
		return nil, fmt.Errorf("vless: no X25519 key share in hello")
	}
	authKey, err := keyShareKeys.Ecdhe.ECDH(realPub)
	if err != nil || authKey == nil {
		return nil, fmt.Errorf("vless: reality ECDH: %w", err)
	}
	verifier.authKey = authKey
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, fmt.Errorf("vless: reality hkdf: %w", err)
	}
	block, _ := aes.NewCipher(authKey)
	gcm, _ := cipher.NewGCM(block)
	gcm.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("vless: reality handshake: %w", err)
	}
	if !verifier.verified {
		// Server is not a REALITY endpoint for our key: fall through like a
		// browser (matches xray/sing-box behavior) and fail the dial.
		uConn.Close()
		return nil, fmt.Errorf("vless: reality verification failed")
	}
	return uConn, nil
}

// writeVLESSHead writes the VLESS request header for a TCP proxy to addr.
// Format (xray/sing VLESS): version(1)=0 | uuid(16) | addonsLen(1)=0 |
// cmd(1)=1 TCP | port(2 BE) | addrType(1) | addr. Domain form for names.
func (v *VLESSDialer) writeVLESSHead(conn net.Conn, addr string) error {
	uid, err := parseUUID(v.UUID)
	if err != nil {
		return err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("vless: bad destination %q: %w", addr, err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return err
	}

	head := make([]byte, 0, 26)
	head = append(head, 0) // version
	head = append(head, uid[:]...)
	head = append(head, 0) // addons length: none (no flow)
	head = append(head, 1) // command: TCP
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	head = append(head, portBytes[:]...) // port BEFORE address (VLESS)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			head = append(head, 1) // 0x01 = IPv4
			head = append(head, ip4...)
		} else {
			head = append(head, 3) // 0x03 = IPv6
			head = append(head, ip.To16()...)
		}
	} else {
		head = append(head, 2, byte(len(host))) // 0x02 = FQDN
		head = append(head, host...)
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write(head)
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}

	// The server prefixes its first Write with a 2-byte response header
	// (version=0, addonsLen=0) per the VLESS protocol. It is only produced
	// together with the first proxied data, so consume it lazily on the
	// first Read to avoid deadlocking against servers that wait for input.
	return nil
}

// vlessRespConn strips the one-time 2-byte VLESS server response header
// (version, addonsLen + optional addons) from the beginning of the stream.
type vlessRespConn struct {
	net.Conn
	pending []byte // header bytes already consumed but not yet delivered
	done    bool
}

func (c *vlessRespConn) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if !c.done {
		var head [2]byte
		if _, err := io.ReadFull(c.Conn, head[:]); err != nil {
			return 0, fmt.Errorf("vless: read response header: %w", err)
		}
		if head[0] != 0 {
			return 0, fmt.Errorf("vless: unknown response version %d", head[0])
		}
		if head[1] > 0 {
			addons := make([]byte, head[1])
			if _, err := io.ReadFull(c.Conn, addons); err != nil {
				return 0, fmt.Errorf("vless: read response addons: %w", err)
			}
		}
		c.done = true
	}
	return c.Conn.Read(b)
}

func filterCurves(curves []utls.CurveID, drop utls.CurveID) []utls.CurveID {
	out := curves[:0]
	for _, c := range curves {
		if c != drop {
			out = append(out, c)
		}
	}
	return out
}

func filterShares(shares []utls.KeyShare, drop utls.CurveID) []utls.KeyShare {
	out := shares[:0]
	for _, s := range shares {
		if s.Group != drop {
			out = append(out, s)
		}
	}
	return out
}

// realityVerifier mirrors sing-box's client-side REALITY verification: the
// relay/endpoint's leaf certificate carries the server's Ed25519 REALITY key
// in place of a real signature; HMAC(authKey, pub) must match.
type realityVerifier struct {
	UConn      *utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

var utlsPeerCertificatesField, _ = reflect.TypeOf(utls.Conn{}).FieldByName("peerCertificates")

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	certs := *(*[]*x509.Certificate)(unsafe.Add(unsafe.Pointer(c.UConn.Conn), utlsPeerCertificatesField.Offset))
	if len(certs) == 0 {
		return fmt.Errorf("vless: no peer certificates")
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

// parseUUID parses the canonical 8-4-4-4-12 hex form into 16 bytes.
func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			continue
		}
		clean = append(clean, c)
	}
	if len(clean) != 32 {
		return out, fmt.Errorf("vless: invalid uuid %q", s)
	}
	for i := 0; i < 16; i++ {
		hi, ok1 := hexVal(clean[i*2])
		lo, ok2 := hexVal(clean[i*2+1])
		if !ok1 || !ok2 {
			return out, fmt.Errorf("vless: invalid uuid %q", s)
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func parsePort(s string) (uint16, error) {
	var p int
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("vless: invalid port %q", s)
		}
		p = p*10 + int(s[i]-'0')
		if p > 65535 {
			return 0, fmt.Errorf("vless: invalid port %q", s)
		}
	}
	return uint16(p), nil
}

// Compile-time assertions that we only depend on stable crypto/tls surface.
var _ = tls.VersionTLS13
