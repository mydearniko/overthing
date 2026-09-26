package tunnel

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// wsConn implements net.Conn over a WebSocket connection, treating every
// payload as a binary data frame. Only the subset of the protocol needed for
// a point-to-point byte tunnel is implemented: binary frames with masking,
// server ping (answered with pong), and close.
type wsConn struct {
	conn net.Conn
	br   *bufio.Reader

	// readBuf carries payload bytes already read from a data frame.
	readBuf   []byte
	closeSent bool
}

func newBufReader(c net.Conn) *bufio.Reader {
	return bufio.NewReaderSize(c, 32*1024)
}

func newWSConn(c net.Conn) *wsConn {
	return &wsConn{conn: c, br: newBufReader(c)}
}

// wsOpCode values used by the tunnel.
const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

func wsMaskKey() [4]byte {
	var k [4]byte
	_, _ = rand.Read(k[:])
	return k
}

// writeFrame writes one client->server frame with masking as required by
// RFC 6455 for clients.
func (w *wsConn) writeFrame(op byte, payload []byte) error {
	var hdr [14]byte
	hdr[0] = 0x80 | op // FIN + opcode
	n := len(payload)
	idx := 2
	switch {
	case n < 126:
		hdr[1] = 0x80 | byte(n)
	case n <= 0xFFFF:
		hdr[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		idx = 4
	default:
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		idx = 10
	}
	key := wsMaskKey()
	copy(hdr[idx:idx+4], key[:])
	idx += 4

	if _, err := w.conn.Write(hdr[:idx]); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	masked := make([]byte, n)
	for i, b := range payload {
		masked[i] = b ^ key[i%4]
	}
	_, err := w.conn.Write(masked)
	return err
}

// readFrame reads one frame from the wire. Control frames are handled
// internally; data frame payloads are returned.
func (w *wsConn) readFrame() (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(w.br, h[:]); err != nil {
		return 0, nil, err
	}
	op := h[0] & 0x0F
	masked := h[1]&0x80 != 0
	length := uint64(h[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.br, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(w.br, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return op, payload, nil
}

func (w *wsConn) Read(p []byte) (int, error) {
	for {
		if len(w.readBuf) > 0 {
			n := copy(p, w.readBuf)
			w.readBuf = w.readBuf[n:]
			return n, nil
		}
		op, payload, err := w.readFrame()
		if err != nil {
			return 0, err
		}
		switch op {
		case wsOpBinary, wsOpText, wsOpContinuation:
			if len(payload) == 0 {
				continue
			}
			w.readBuf = payload
		case wsOpPing:
			if err := w.writeFrame(wsOpPong, payload); err != nil {
				return 0, err
			}
		case wsOpPong:
			// ignore
		case wsOpClose:
			_ = w.writeFrame(wsOpClose, nil)
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("unexpected websocket opcode: 0x%02X", op)
		}
	}
}

func (w *wsConn) Write(p []byte) (int, error) {
	if w.closeSent {
		return 0, io.ErrClosedPipe
	}
	if err := w.writeFrame(wsOpBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) Close() error {
	if !w.closeSent {
		w.closeSent = true
		// Best effort close frame; ignore errors.
		_ = w.conn.SetWriteDeadline(writeDeadline())
		_ = w.writeFrame(wsOpClose, nil)
	}
	return w.conn.Close()
}

func writeDeadline() time.Time {
	return time.Now().Add(2 * time.Second)
}

func (w *wsConn) LocalAddr() net.Addr  { return w.conn.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr { return w.conn.RemoteAddr() }

func (w *wsConn) SetDeadline(t time.Time) error      { return w.conn.SetDeadline(t) }
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }
