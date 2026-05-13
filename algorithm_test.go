// Copyright 2026 Johan Stenstam. All rights reserved.
// Use of this source code is governed by a BSD-style
// license.

package dns

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
)

// testAlgNum is an IANA-Unassigned codepoint used only by this test
// file to exercise the algorithm registration API end-to-end.
const testAlgNum uint8 = 200

// testAlg is an Algorithm implementation backed by ed25519. It only
// validates the registration plumbing — the crypto is delegated to
// the stdlib so the test stays focused on dispatch correctness.
type testAlg struct{}

func (testAlg) Number() uint8     { return testAlgNum }
func (testAlg) Name() string      { return "TESTALG" }
func (testAlg) Hash() crypto.Hash { return 0 }

func (testAlg) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, ErrKeySize
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func (testAlg) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	if len(buf) != ed25519.PublicKeySize {
		return nil, ErrKey
	}
	return ed25519.PublicKey(buf), nil
}

func (testAlg) PublicKeyToWire(pub crypto.PublicKey) ([]byte, error) {
	p, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, ErrKey
	}
	return []byte(p), nil
}

func (testAlg) ReadPrivateKey(m map[string]string) (crypto.PrivateKey, error) {
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

func (testAlg) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	p, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return "", ErrPrivKey
	}
	return "PrivateKey: " + toBase64(p.Seed()) + "\n", nil
}

func (testAlg) Verify(pub crypto.PublicKey, hashed, sig []byte) error {
	p, ok := pub.(ed25519.PublicKey)
	if !ok {
		return ErrKey
	}
	if ed25519.Verify(p, hashed, sig) {
		return nil
	}
	return ErrSig
}

func (testAlg) SignaturePostProcess(sig []byte) ([]byte, error) {
	return sig, nil
}

// Register the test algorithm once at package init.
var _ = func() bool {
	if err := RegisterAlgorithm(&testAlg{}); err != nil {
		panic("dns: testAlg registration failed: " + err.Error())
	}
	return true
}()

// shadowAlg is used only to confirm the built-in check rejects
// re-registration of a stdlib-implemented algorithm number.
type shadowAlg struct{ testAlg }

func (shadowAlg) Number() uint8 { return RSASHA256 }

func TestRegisterAlgorithm_BuiltinRejected(t *testing.T) {
	err := RegisterAlgorithm(&shadowAlg{})
	if !errors.Is(err, ErrAlgBuiltin) {
		t.Fatalf("got %v, want ErrAlgBuiltin", err)
	}
}

func TestRegisterAlgorithm_ConflictRejected(t *testing.T) {
	err := RegisterAlgorithm(&testAlg{})
	if !errors.Is(err, ErrAlgRegistered) {
		t.Fatalf("got %v, want ErrAlgRegistered", err)
	}
}

func TestRegisterAlgorithm_MapsUpdated(t *testing.T) {
	if name := AlgorithmToString[testAlgNum]; name != "TESTALG" {
		t.Errorf("AlgorithmToString[%d] = %q, want TESTALG", testAlgNum, name)
	}
	if h := AlgorithmToHash[testAlgNum]; h != 0 {
		t.Errorf("AlgorithmToHash[%d] = %v, want 0", testAlgNum, h)
	}
}

func TestRegisteredAlgorithm_GenerateAndKeyRoundTrip(t *testing.T) {
	k := &DNSKEY{
		Hdr:       RR_Header{Name: "miek.nl.", Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: testAlgNum,
	}
	priv, err := k.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if k.PublicKey == "" {
		t.Fatal("DNSKEY.PublicKey not set by Generate")
	}

	pkstr := k.PrivateKeyString(priv)
	if pkstr == "" {
		t.Fatal("PrivateKeyString returned empty")
	}

	k2 := &DNSKEY{Algorithm: testAlgNum, PublicKey: k.PublicKey}
	priv2, err := k2.NewPrivateKey(pkstr)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	if !bytes.Equal(priv.(ed25519.PrivateKey), priv2.(ed25519.PrivateKey)) {
		t.Errorf("roundtrip key mismatch")
	}
}

func TestRegisteredAlgorithm_RRSIG(t *testing.T) {
	k := &DNSKEY{
		Hdr:       RR_Header{Name: "miek.nl.", Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: testAlgNum,
	}
	priv, err := k.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatal("Generate did not return a crypto.Signer")
	}

	rr := &A{
		Hdr: RR_Header{Name: "miek.nl.", Rrtype: TypeA, Class: ClassINET, Ttl: 3600},
		A:   net.ParseIP("1.2.3.4").To4(),
	}

	rrsig := &RRSIG{
		Hdr:        RR_Header{Name: "miek.nl.", Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 3600},
		Algorithm:  testAlgNum,
		KeyTag:     k.KeyTag(),
		SignerName: "miek.nl.",
		Inception:  1,
		Expiration: 1<<32 - 1,
	}
	if err := rrsig.Sign(signer, []RR{rr}); err != nil {
		t.Fatalf("RRSIG.Sign: %v", err)
	}
	if err := rrsig.Verify(k, []RR{rr}); err != nil {
		t.Fatalf("RRSIG.Verify: %v", err)
	}
}

func TestRegisteredAlgorithm_SIG0(t *testing.T) {
	k := &KEY{DNSKEY: DNSKEY{
		Hdr:       RR_Header{Name: "miek.nl.", Rrtype: TypeKEY, Class: ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: testAlgNum,
	}}
	priv, err := k.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatal("Generate did not return a crypto.Signer")
	}

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	sig := &SIG{RRSIG: RRSIG{
		Hdr:        RR_Header{Name: ".", Rrtype: TypeSIG, Class: ClassANY, Ttl: 0},
		Algorithm:  testAlgNum,
		KeyTag:     k.KeyTag(),
		SignerName: "miek.nl.",
		Inception:  1,
		Expiration: 1<<32 - 1,
	}}
	buf, err := sig.Sign(signer, m)
	if err != nil {
		t.Fatalf("SIG.Sign: %v", err)
	}
	if err := sig.Verify(k, buf); err != nil {
		t.Fatalf("SIG.Verify: %v", err)
	}
}

func TestRegisteredAlgorithm_UnregisteredCodepoint(t *testing.T) {
	// An unregistered codepoint must surface as ErrAlg in the
	// signing path. Using 201 (Unassigned, no init() registration).
	k := &DNSKEY{
		Hdr:       RR_Header{Name: "miek.nl.", Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: 201,
	}
	if _, err := k.Generate(0); !errors.Is(err, ErrAlg) {
		t.Fatalf("Generate(201) returned %v, want ErrAlg", err)
	}
}
