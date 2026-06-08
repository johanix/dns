// Copyright 2026 Johan Stenstam. All rights reserved.
// Use of this source code is governed by a BSD-style
// license.

package dns

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// largeKeyAlgNum is an IANA-Unassigned codepoint used only by this
// test to exercise the DNSKEY-packing scratch buffers with a public
// key larger than DefaultMsgSize (the situation post-quantum
// algorithms such as QR-UOV create).
const largeKeyAlgNum uint8 = 210

// largeKeyPad is the size of the synthetic prefix that inflates the
// wire public key past DefaultMsgSize (4096). 24 KB mirrors the
// ~23.6 KB QR-UOV-I DNSKEY.
const largeKeyPad = 24 * 1024

// largeKeyAlg is an Algorithm whose on-the-wire public key is a fixed
// largeKeyPad-byte block followed by a real 32-byte ed25519 key. The
// crypto is delegated to ed25519; the pad exists only to force the
// DNSKEY RDATA over DefaultMsgSize so the KeyTag / ToDS / RRSIG
// packing paths must size their buffers to the key, not to the 4 KB
// default.
type largeKeyAlg struct{}

func (largeKeyAlg) Name() string      { return "LARGEKEYTEST" }
func (largeKeyAlg) Hash() crypto.Hash { return 0 }

func (largeKeyAlg) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, ErrKeySize
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func (largeKeyAlg) PublicKeyToWire(pub crypto.PublicKey) ([]byte, error) {
	p, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, ErrKey
	}
	out := make([]byte, largeKeyPad+len(p))
	copy(out[largeKeyPad:], p)
	return out, nil
}

func (largeKeyAlg) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	if len(buf) != largeKeyPad+ed25519.PublicKeySize {
		return nil, ErrKey
	}
	return ed25519.PublicKey(buf[largeKeyPad:]), nil
}

func (largeKeyAlg) ReadPrivateKey(m map[string]string) (crypto.PrivateKey, error) {
	seedStr, ok := m["privatekey"]
	if !ok {
		return nil, ErrPrivKey
	}
	seed, err := fromBase64([]byte(seedStr))
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, ErrPrivKey
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (largeKeyAlg) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	p, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return "", ErrPrivKey
	}
	return "PrivateKey: " + toBase64(p.Seed()) + "\n", nil
}

func (largeKeyAlg) Verify(pub crypto.PublicKey, hashed, sig []byte) error {
	p, ok := pub.(ed25519.PublicKey)
	if !ok {
		return ErrKey
	}
	if ed25519.Verify(p, hashed, sig) {
		return nil
	}
	return ErrSig
}

func (largeKeyAlg) SignaturePostProcess(sig []byte) ([]byte, error) { return sig, nil }

var _ = func() bool {
	if err := RegisterAlgorithm(largeKeyAlgNum, &largeKeyAlg{}); err != nil {
		panic("dns: largeKeyAlg registration failed: " + err.Error())
	}
	return true
}()

// newLargeKeyDNSKEY generates a DNSKEY whose wire RDATA exceeds
// DefaultMsgSize.
func newLargeKeyDNSKEY(t *testing.T) (*DNSKEY, crypto.Signer) {
	t.Helper()
	k := &DNSKEY{
		Hdr:       RR_Header{Name: "example.com.", Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: largeKeyAlgNum,
	}
	priv, err := k.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Sanity: the base64 public key must decode to more than
	// DefaultMsgSize, otherwise the test isn't exercising the fix.
	raw, err := fromBase64([]byte(k.PublicKey))
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(raw) <= DefaultMsgSize {
		t.Fatalf("public key %d bytes, expected > DefaultMsgSize (%d)", len(raw), DefaultMsgSize)
	}
	return k, priv.(crypto.Signer)
}

// TestKeyTagLargeKey verifies KeyTag() returns a stable non-zero value
// for a DNSKEY larger than DefaultMsgSize. Before the buffer fix this
// returned 0 (packKeyWire overflowed the 4 KB scratch buffer).
func TestKeyTagLargeKey(t *testing.T) {
	k, _ := newLargeKeyDNSKEY(t)
	kt := k.KeyTag()
	if kt == 0 {
		t.Fatal("KeyTag() == 0 for a >4 KB key (scratch buffer overflow not fixed)")
	}
	if kt2 := k.KeyTag(); kt2 != kt {
		t.Fatalf("KeyTag() not stable: %d then %d", kt, kt2)
	}
}

// TestToDSLargeKey verifies ToDS() succeeds for a large key (it
// returned nil before the fix because packKeyWire overflowed).
func TestToDSLargeKey(t *testing.T) {
	k, _ := newLargeKeyDNSKEY(t)
	ds := k.ToDS(SHA256)
	if ds == nil {
		t.Fatal("ToDS() == nil for a >4 KB key")
	}
	if ds.KeyTag != k.KeyTag() {
		t.Fatalf("DS.KeyTag %d != DNSKEY.KeyTag %d", ds.KeyTag, k.KeyTag())
	}
	if ds.Algorithm != k.Algorithm {
		t.Fatalf("DS.Algorithm %d != %d", ds.Algorithm, k.Algorithm)
	}
}

// TestRRSIGLargeKeyRoundTrip is the end-to-end proof: sign an RRset
// with a large-key DNSKEY and verify it. Verify compares
// rr.KeyTag against k.KeyTag(); both must now agree on a real
// non-zero tag.
func TestRRSIGLargeKeyRoundTrip(t *testing.T) {
	k, signer := newLargeKeyDNSKEY(t)

	a := &A{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeA, Class: ClassINET, Ttl: 3600}}
	a.A = []byte{192, 0, 2, 1}
	rrset := []RR{a}

	now := time.Now()
	rrsig := &RRSIG{
		Hdr:         RR_Header{Name: "example.com.", Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 3600},
		TypeCovered: TypeA,
		Algorithm:   largeKeyAlgNum,
		Labels:      2,
		OrigTtl:     3600,
		Expiration:  uint32(now.Add(24 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-time.Hour).Unix()),
		KeyTag:      k.KeyTag(),
		SignerName:  "example.com.",
	}
	if err := rrsig.Sign(signer, rrset); err != nil {
		t.Fatalf("RRSIG.Sign: %v", err)
	}
	if err := rrsig.Verify(k, rrset); err != nil {
		t.Fatalf("RRSIG.Verify: %v", err)
	}

	// Tamper check.
	a.A = []byte{192, 0, 2, 2}
	if err := rrsig.Verify(k, rrset); err == nil {
		t.Fatal("RRSIG.Verify accepted a tampered RRset")
	}
}
