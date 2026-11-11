package dns

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// signedCompressedUpdate returns an UPDATE signed with SIG(0) whose names are
// compressed on the wire, the way BIND's nsupdate sends it, and the KEY that
// verifies it.
func signedCompressedUpdate(t *testing.T) ([]byte, *KEY) {
	t.Helper()
	keyrr := new(KEY)
	keyrr.Hdr = RR_Header{Name: "upd.example.", Rrtype: TypeKEY, Class: ClassINET}
	keyrr.Algorithm = ED25519
	keyrr.Protocol = 3
	pk, err := keyrr.Generate(256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	m := new(Msg)
	m.SetUpdate("example.")
	m.Insert([]RR{testRR("a.example. 60 IN A 192.0.2.1"), testRR("b.example. 60 IN A 192.0.2.2")})
	m.Compress = true

	now := uint32(time.Now().Unix())
	sig := new(SIG)
	sig.Algorithm = ED25519
	sig.Expiration = now + 300
	sig.Inception = now - 300
	sig.KeyTag = keyrr.KeyTag()
	sig.SignerName = keyrr.Hdr.Name
	wire, err := sig.Sign(pk.(crypto.Signer), m)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return wire, keyrr
}

// rawRequestHandler records what RawRequest returned and whether the SIG(0)
// verifies over it, and over the parsed message packed again.
type rawRequestHandler struct {
	got          chan []byte
	verifiesRaw  chan error
	verifiesRepk chan error
	key          *KEY
}

func (h *rawRequestHandler) ServeDNS(w ResponseWriter, r *Msg) {
	rr, ok := w.(RawRequester)
	if !ok {
		h.got <- nil
		return
	}
	raw := rr.RawRequest()
	h.got <- raw
	if n := len(r.Extra); n > 0 && h.key != nil {
		if sig, ok := r.Extra[n-1].(*SIG); ok {
			h.verifiesRaw <- sig.Verify(h.key, raw)
			repacked, err := r.Pack()
			if err != nil {
				h.verifiesRepk <- err
			} else {
				h.verifiesRepk <- sig.Verify(h.key, repacked)
			}
		}
	}
	m := new(Msg)
	m.SetReply(r)
	w.WriteMsg(m)
}

func TestRawRequestKeepsSignedRequestAsSent(t *testing.T) {
	wire, key := signedCompressedUpdate(t)

	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			h := &rawRequestHandler{got: make(chan []byte, 1), verifiesRaw: make(chan error, 1),
				verifiesRepk: make(chan error, 1), key: key}
			var s *Server
			var addr string
			var err error
			if proto == "udp" {
				s, addr, _, err = RunLocalUDPServer(":0", acceptAll(h))
			} else {
				s, addr, _, err = RunLocalTCPServer(":0", acceptAll(h))
			}
			if err != nil {
				t.Fatalf("server: %v", err)
			}
			defer s.Shutdown()

			sendRaw(t, proto, addr, wire)

			raw := recv(t, h.got, "RawRequest")
			if !bytes.Equal(raw, wire) {
				t.Fatalf("RawRequest = %d bytes, want the %d bytes sent", len(raw), len(wire))
			}
			if err := recv(t, h.verifiesRaw, "verify over RawRequest"); err != nil {
				t.Errorf("SIG(0) over RawRequest: %v, want it to verify", err)
			}
			// The point of RawRequest: the parsed message packed again has
			// no compression, so the signature does not cover it.
			if err := recv(t, h.verifiesRepk, "verify over a re-pack"); err == nil {
				t.Errorf("SIG(0) verified over a re-pack of a compressed request; the test no longer shows the difference")
			}
		})
	}
}

func TestRawRequestNilWithoutSIG(t *testing.T) {
	h := &rawRequestHandler{got: make(chan []byte, 2)}
	s, addr, _, err := RunLocalTCPServer(":0", acceptAll(h))
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("example.", TypeSOA)
	m.SetEdns0(1232, false)
	c := &Client{Net: "tcp"}
	if _, _, err := c.Exchange(m, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if raw := recv(t, h.got, "RawRequest"); raw != nil {
		t.Errorf("RawRequest = %d bytes for a request without a SIG, want nil", len(raw))
	}
}

// acceptAll serves with h and accepts every opcode: the default
// MsgAcceptFunc answers UPDATE with NOTIMP before any handler runs.
func acceptAll(h Handler) func(*Server) {
	return func(srv *Server) {
		srv.Handler = h
		srv.MsgAcceptFunc = func(Header) MsgAcceptAction { return MsgAccept }
	}
}

// recv waits for one value, failing the test instead of hanging.
func recv[T any](t *testing.T, ch chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatalf("no %s within 3s", what)
		var zero T
		return zero
	}
}

// sendRaw sends one request exactly as given and waits for the answer.
func sendRaw(t *testing.T, proto, addr string, wire []byte) {
	t.Helper()
	conn, err := net.DialTimeout(proto, addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	out := wire
	if proto == "tcp" {
		out = make([]byte, 2+len(wire))
		binary.BigEndian.PutUint16(out, uint16(len(wire)))
		copy(out[2:], wire)
	}
	if _, err := conn.Write(out); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read answer: %v", err)
	}
}
