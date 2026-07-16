# johanix/dns — divergence from upstream miekg/dns

This is the `johanix/dns` fork of [`miekg/dns`](https://github.com/miekg/dns).
This document tracks every change the fork carries on top of upstream, so the
divergence stays legible as the fork grows.

**Upstream base:** miekg/dns **v1.1.72** (`cb21f4d2`, released 2026-01-22).
**Johanix baseline tag:** `v1.1.72-johanix.1`.

Branch model:

- `master` is a **pristine mirror of upstream miekg** — never branch off it for
  fork work and never open a PR into it.
- `main` is the fork's default / integration branch: `master` **plus** the
  johanix changes below. All fork work branches off `main` and merges back into
  `main`.

The authoritative list of divergences is `git log master..main`. Each entry
below corresponds to one logical change on that list.

---

## 1. Out-of-tree DNSSEC algorithm registry

- **Implemented:** 2026-05-13 (refined 2026-05-14 … 2026-05-15)
- **Commits:** `747cbcbc`, `a4e41a4b`, `3300006a`
- **Files / symbols:**
  - `algorithm.go` (new): `Algorithm` interface;
    `RegisterAlgorithm(num uint8, impl Algorithm) error`; sentinel errors
    `ErrAlgRegistered`, `ErrAlgBuiltin`; `builtinAlgorithms` guard set;
    `algRegistry` / `algRegistryMu`; `lookupAlgorithm`.
  - Registration also populates the existing public maps `AlgorithmToString`,
    `AlgorithmToHash`, and **`StringToAlgorithm`** (name → number), so callers
    that read those maps directly observe the new algorithm.
  - Dispatch wiring so a registered algorithm works everywhere the library
    accepts an algorithm number: `dnssec.go`, `dnssec_keygen.go`,
    `dnssec_keyscan.go`, `dnssec_privkey.go`, `sig0.go`.
  - Tests: `algorithm_test.go`.
- **Why:** let an application register a signature algorithm the library does
  not implement in-tree (notably post-quantum algorithms such as ML-DSA /
  FALCON / SQIsign / QR-UOV) at a **caller-supplied IANA codepoint**, without
  patching the library's built-in per-algorithm switches. The codepoint choice
  is the caller's; built-in numbers cannot be shadowed (`ErrAlgBuiltin`) and a
  number cannot be registered twice (`ErrAlgRegistered`).

## 2. DNSKEY scratch-buffer sizing for large PQ keys

- **Implemented:** 2026-06-08
- **Commits:** `5084720e` (merge `2a28f8f1`)
- **Files / symbols:**
  - `dnssec.go`: `(*DNSKEY).KeyTag()` and `(*DNSKEY).ToDS()` now size their
    key-packing scratch buffers to `max(DefaultMsgSize, keywire.packedLen())`;
    new helper `(*dnskeyWireFmt).packedLen()`.
  - Tests: `dnssec_largekey_test.go`.
- **Why:** `KeyTag()` and `ToDS()` packed the DNSKEY RDATA into a fixed
  `DefaultMsgSize` (4096-byte) buffer. A post-quantum public key larger than
  that (e.g. QR-UOV-I at ~23.6 KB) overflowed `packKeyWire`, so `KeyTag()`
  silently returned 0 and `ToDS()` returned nil; a zero KeyTag then trips the
  `rr.KeyTag != k.KeyTag()` guard in `RRSIG.Verify`, making high-level RRSIG
  verification impossible for large keys. `DefaultMsgSize` remains a floor, so
  allocation behavior is unchanged for all existing (sub-4 KB) keys.

## 3. RFC 2136 §2.5.2 delete-RRset `*ANY` unpack

- **Implemented:** 2026-07-09 (cherry-picked; original author date 2026-04-27)
- **Commits:** `c8cb509a` (tests), `79943c83` (`msg.go`)
- **Files / symbols:**
  - `msg.go`: `UnpackRRWithHeader` returns `&ANY{Hdr: h}` for any record with
    `Class == ClassANY && Rdlength == 0 && Rrtype != TypeANY`.
  - Tests: `update_delete_test.go` (delete-RRset / delete-RR pack + SIG(0)
    round-trip).
- **Why:** RFC 2136 §2.5.2 "delete RRset" placeholders carry `CLASS=ANY` with no
  rdata. Previously these were unpacked into a typed RR (e.g. `*DS`) with
  zero-valued scalar fields; most per-type `pack()` methods unconditionally
  serialize their fixed-size fields, so `unpack → pack` was not byte-identical
  and SIG(0) verification of inbound UPDATE messages failed with
  "dns: bad signature". Returning `*ANY` matches what the high-level
  `Msg.RemoveRRset` constructor produces and keeps the round-trip symmetric.

## 4. `oots` SVCB SvcParamKey (IANA SvcParamKey 12)

- **Implemented:** 2026-07-16
- **Files / symbols:**
  - `svcb.go`: constant `SVCB_OOTS SVCBKey = 12` (explicit jump to the IANA
    number; the preceding keys are iota-sequential and end at `SVCB_OHTTP` = 8);
    types `SVCBOots` (field `Oots []SVCBOotsEntry`) and `SVCBOotsEntry`
    (`Proto string`, `Weight uint8`) implementing `SVCBKeyValue`
    (`Key`/`pack`/`unpack`/`String`/`parse`/`copy`/`len`); recognized-protocol
    set `svcbOotsKnownProtos` (`do53`, `dot`, `doh`, `doq`); registry wiring in
    `svcbKeyToStringMap` (`SVCB_OOTS → "oots"`, reverse map derived) and
    `makeSVCBKeyValue`.
  - Tests: `svcb_test.go`.
- **Why:** implement the `"oots"` ("Opportunistic Operator-led Transport
  Signal") SvcParamKey from `draft-johani-dnsop-svcb-oots`. It advertises, per
  DNS transport protocol, the operator's confidence (as a percentage,
  0–100) that it can serve the nameserver's total query load over that
  transport. Codec semantics from the draft: wire entry is
  `[len L][L octets proto][weight]` concatenated (N ≥ 1); unrecognized protocols
  are ignored (never an error); a wire weight > 100 is clamped to 100 (never
  malformed); a duplicate protocol identifier makes the RR malformed and is
  rejected by both `unpack` and `parse`; presentation form is
  `oots="proto:weight[,proto:weight]*"` with insignificant order. The
  absence-default rules (`do53` → 100, others → 0) and "ignore in AliasMode" are
  consumer rules and are documented on `SVCBOots` but not enforced by the codec.

---

## Appending to this document

This is a living document. When the fork gains another change on top of
upstream, add a new numbered section here in the same format
(short name, implemented date from `git log --format=%ci`, commits, files /
symbols, why). Keep the entries in the order the changes landed, and leave the
upstream-base line at the top current if the fork is ever rebased onto a newer
upstream release.
