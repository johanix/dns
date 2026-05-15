// Copyright 2026 Johan Stenstam. All rights reserved.
// Use of this source code is governed by a BSD-style
// license.

package dns

import (
	"crypto"
	"fmt"
	"sync"
)

// Algorithm is the interface implemented by an out-of-tree DNSSEC
// signature algorithm. The codepoint (IANA "DNS Security Algorithm
// Numbers" or the private use range in PRIVATEDNS / PRIVATEOID
// semantics) is not part of the Algorithm itself — the application
// chooses one and binds it at [RegisterAlgorithm] time.
//
// Built-in algorithms (RSASHA*, ECDSAP*, ED25519, ED448) are not
// implemented through this interface — they live in the existing
// per-algorithm switches and cannot be re-registered.
//
// Typical pattern (application init function):
//
//	import (
//	    "github.com/miekg/dns"
//	    "github.com/johanix/dnssec-algorithms/mldsa44"
//	)
//
//	func init() {
//	    dns.RegisterAlgorithm(199, mldsa44.New())
//	}
//
// All methods may be called concurrently. Methods are expected to be
// stateless or use their own synchronization.
type Algorithm interface {
	// Name is the short upper-case name used in private key files
	// ("Algorithm: <num> (<name>)") and in [AlgorithmToString] output.
	Name() string

	// Hash returns the [crypto.Hash] applied to the signed bytes
	// before passing them to [crypto.Signer.Sign] and to [Verify].
	// Return 0 for identity-hash algorithms (ED25519, ML-DSA, ...)
	// where the full wire bytes reach the signer unchanged.
	Hash() crypto.Hash

	// Generate returns a fresh keypair. bits is the caller's size
	// hint; algorithms with fixed parameters should require bits == 0
	// and return [ErrKeySize] otherwise. The returned private key
	// must satisfy [crypto.Signer] so the shared sign path can use it.
	Generate(bits int) (crypto.PrivateKey, error)

	// PublicKeyFromWire decodes a DNSKEY/KEY rdata public key field
	// into a [crypto.PublicKey]. The input is the raw key bytes
	// (already base64-decoded from DNSKEY.PublicKey).
	PublicKeyFromWire(keybuf []byte) (crypto.PublicKey, error)

	// PublicKeyToWire is the inverse: encode a [crypto.PublicKey]
	// into the DNSKEY rdata public-key bytes (pre-base64).
	PublicKeyToWire(pub crypto.PublicKey) ([]byte, error)

	// ReadPrivateKey parses a BIND-style private-key file's
	// key-material lines (already lexed into a map[name]value, with
	// names lower-cased) into a [crypto.PrivateKey].
	ReadPrivateKey(fields map[string]string) (crypto.PrivateKey, error)

	// PrivateKeyToString serializes the private key into the
	// BIND-style "Field: <base64>" lines that follow the
	// "Private-key-format" and "Algorithm" header lines. The caller
	// supplies the headers; this method returns only the
	// algorithm-specific body lines.
	PrivateKeyToString(priv crypto.PrivateKey) (string, error)

	// Verify checks a signature. hashed is the [Hash]-processed
	// bytes (or raw bytes for identity-hash algorithms). sig is the
	// signature exactly as it appears on the wire (after any
	// algorithm-specific post-processing applied by the signer).
	// Returns nil on success, [ErrSig] on signature mismatch, or
	// another error for malformed input.
	Verify(pub crypto.PublicKey, hashed, sig []byte) error

	// SignaturePostProcess shapes the output of [crypto.Signer.Sign]
	// before it is written to the wire. Built-in ECDSA strips ASN.1
	// DER; built-in RSA and ED25519 are pass-through. Most
	// implementations can return sig unchanged.
	SignaturePostProcess(sig []byte) ([]byte, error)
}

// Errors returned by [RegisterAlgorithm].
var (
	// ErrAlgRegistered indicates the algorithm number is already
	// registered by another implementation. Re-registration is not
	// allowed; an init-time conflict between two side-effect imports
	// must be resolved by the user.
	ErrAlgRegistered = fmt.Errorf("dns: algorithm number already registered")

	// ErrAlgBuiltin indicates the algorithm number is implemented
	// by the library itself (RSASHA*, ECDSAP*, ED25519, ED448) and
	// cannot be overridden through the registry.
	ErrAlgBuiltin = fmt.Errorf("dns: algorithm number is built-in")
)

// builtinAlgorithms is the set of algorithm numbers implemented by
// the library's per-algorithm switches. RegisterAlgorithm refuses to
// shadow any of these.
var builtinAlgorithms = map[uint8]struct{}{
	RSAMD5:           {},
	DSA:              {},
	RSASHA1:          {},
	DSANSEC3SHA1:     {},
	RSASHA1NSEC3SHA1: {},
	RSASHA256:        {},
	RSASHA512:        {},
	ECCGOST:          {},
	ECDSAP256SHA256:  {},
	ECDSAP384SHA384:  {},
	ED25519:          {},
}

var (
	algRegistryMu sync.RWMutex
	algRegistry   = map[uint8]Algorithm{}
)

// RegisterAlgorithm wires impl into the dispatch tables under the
// IANA DNS Security Algorithm Number num. The algorithm becomes
// usable everywhere the library accepts an [Algorithm] number for
// sign, verify, key generation, and BIND-style key file parsing.
//
// The caller (typically an application's init function) owns the
// codepoint choice. num must not be one implemented by a built-in
// (ErrAlgBuiltin), and must not already be taken by a previous
// Register call (ErrAlgRegistered).
//
// Successful registration also populates [AlgorithmToString],
// [AlgorithmToHash], and [StringToAlgorithm] so callers that read
// those maps directly observe the new algorithm.
//
// RegisterAlgorithm is safe to call from multiple init goroutines.
func RegisterAlgorithm(num uint8, impl Algorithm) error {
	if _, builtin := builtinAlgorithms[num]; builtin {
		return fmt.Errorf("%w: %d", ErrAlgBuiltin, num)
	}
	algRegistryMu.Lock()
	defer algRegistryMu.Unlock()
	if _, exists := algRegistry[num]; exists {
		return fmt.Errorf("%w: %d", ErrAlgRegistered, num)
	}
	algRegistry[num] = impl
	AlgorithmToString[num] = impl.Name()
	AlgorithmToHash[num] = impl.Hash()
	// StringToAlgorithm is the package-level reverse map of
	// AlgorithmToString; callers (e.g. zone parser, CLI tooling)
	// look up algorithm numbers by name. Keep it in sync so the
	// just-registered algorithm is reachable by name.
	StringToAlgorithm[impl.Name()] = num
	return nil
}

// lookupAlgorithm returns the registered implementation for num, or
// nil, false if none is registered. Built-in algorithm numbers always
// return nil, false — built-ins are handled in the per-algorithm
// switches and never reach the registry.
func lookupAlgorithm(num uint8) (Algorithm, bool) {
	algRegistryMu.RLock()
	defer algRegistryMu.RUnlock()
	impl, ok := algRegistry[num]
	return impl, ok
}
