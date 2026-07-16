package dns

import (
	"testing"
)

// This tests everything valid about SVCB but parsing.
// Parsing tests belong to parse_test.go.
func TestSVCB(t *testing.T) {
	svcbs := []struct {
		key  string
		data string
	}{
		{`mandatory`, `alpn,key65000`},
		{`alpn`, `h2,h2c`},
		{`port`, `499`},
		{`ipv4hint`, `3.4.3.2,1.1.1.1`},
		{`no-default-alpn`, ``},
		{`ipv6hint`, `1::4:4:4:4,1::3:3:3:3`},
		{`ech`, `YUdWc2JHOD0=`},
		{`dohpath`, `/dns-query{?dns}`},
		{`key65000`, `4\ 3`},
		{`key65001`, `\"\ `},
		{`key65002`, ``},
		{`key65003`, `=\"\"`},
		{`key65004`, `\254\ \ \030\000`},
		{`ohttp`, ``},
		{`oots`, `do53:100,dot:5,doq:5`},
	}

	for _, o := range svcbs {
		keyCode := svcbStringToKey(o.key)
		kv := makeSVCBKeyValue(keyCode)
		if kv == nil {
			t.Error("failed to parse svc key: ", o.key)
			continue
		}
		if kv.Key() != keyCode {
			t.Error("key constant is not in sync: ", keyCode)
			continue
		}
		err := kv.parse(o.data)
		if err != nil {
			t.Error("failed to parse svc pair: ", o.key)
			continue
		}
		b, err := kv.pack()
		if err != nil {
			t.Error("failed to pack value of svc pair: ", o.key, err)
			continue
		}
		if len(b) != int(kv.len()) {
			t.Errorf("expected packed svc value %s to be of length %d but got %d", o.key, int(kv.len()), len(b))
		}
		err = kv.unpack(b)
		if err != nil {
			t.Error("failed to unpack value of svc pair: ", o.key, err)
			continue
		}
		if str := kv.String(); str != o.data {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", o.key, o.data, str)
		}
	}
}

func TestDecodeBadSVCB(t *testing.T) {
	svcbs := []struct {
		key  SVCBKey
		data []byte
	}{
		{
			key:  SVCB_ALPN,
			data: []byte{3, 0, 0}, // There aren't three octets after 3
		},
		{
			key:  SVCB_NO_DEFAULT_ALPN,
			data: []byte{0},
		},
		{
			key:  SVCB_PORT,
			data: []byte{},
		},
		{
			key:  SVCB_IPV4HINT,
			data: []byte{0, 0, 0},
		},
		{
			key:  SVCB_IPV6HINT,
			data: []byte{0, 0, 0},
		},
		{
			key:  SVCB_OHTTP,
			data: []byte{0},
		},
		{
			key:  SVCB_OOTS,
			data: []byte{}, // Empty value: fewer than the required one entry.
		},
		{
			key:  SVCB_OOTS,
			data: []byte{0, 100}, // Zero-length protocol identifier (L == 0).
		},
		{
			key:  SVCB_OOTS,
			data: []byte{4, 'd', 'o', '5', '3'}, // Entry truncated: no weight octet.
		},
		{
			key: SVCB_OOTS,
			// do53:1 followed by a second do53:2 -> duplicate identifier.
			data: []byte{4, 'd', 'o', '5', '3', 1, 4, 'd', 'o', '5', '3', 2},
		},
	}
	for _, o := range svcbs {
		err := makeSVCBKeyValue(SVCBKey(o.key)).unpack(o.data)
		if err == nil {
			t.Error("accepted invalid svc value with key ", SVCBKey(o.key).String())
		}
	}
}

func TestPresentationSVCBAlpn(t *testing.T) {
	tests := map[string]string{
		"h2":                "h2",
		"http":              "http",
		"\xfa":              `\250`,
		"some\"other,chars": `some\"other\\\044chars`,
	}
	for input, want := range tests {
		e := new(SVCBAlpn)
		e.Alpn = []string{input}
		if e.String() != want {
			t.Errorf("improper conversion with String(), wanted %v got %v", want, e.String())
		}
	}
}

func TestSVCBAlpn(t *testing.T) {
	tests := map[string][]string{
		`. 1 IN SVCB 10 one.test. alpn=h2`:                                         {"h2"},
		`. 2 IN SVCB 20 two.test. alpn=h2,h3-19`:                                   {"h2", "h3-19"},
		`. 3 IN SVCB 30 three.test. alpn="f\\\\oo\\,bar,h2"`:                       {`f\oo,bar`, "h2"},
		`. 4 IN SVCB 40 four.test. alpn="part1,part2,part3\\,part4\\\\"`:           {"part1", "part2", `part3,part4\`},
		`. 5 IN SVCB 50 five.test. alpn=part1\,\p\a\r\t2\044part3\092,part4\092\\`: {"part1", "part2", `part3,part4\`},
	}
	for s, v := range tests {
		rr, err := NewRR(s)
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		alpn := rr.(*SVCB).Value[0].(*SVCBAlpn).Alpn
		if len(v) != len(alpn) {
			t.Fatalf("parsing alpn failed, wanted %v got %v", v, alpn)
		}
		for i := range v {
			if v[i] != alpn[i] {
				t.Fatalf("parsing alpn failed, wanted %v got %v", v, alpn)
			}
		}
	}
}

func TestCompareSVCB(t *testing.T) {
	val1 := []SVCBKeyValue{
		&SVCBPort{
			Port: 117,
		},
		&SVCBAlpn{
			Alpn: []string{"h2", "h3"},
		},
	}
	val2 := []SVCBKeyValue{
		&SVCBAlpn{
			Alpn: []string{"h2", "h3"},
		},
		&SVCBPort{
			Port: 117,
		},
	}
	if !areSVCBPairArraysEqual(val1, val2) {
		t.Error("svcb pairs were compared without sorting")
	}
	if val1[0].Key() != SVCB_PORT || val2[0].Key() != SVCB_ALPN {
		t.Error("original svcb pairs were reordered during comparison")
	}
}

func ootsEqual(a, b []SVCBOotsEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSVCBOotsWireRoundTrip exercises pack -> unpack for the "oots" key.
func TestSVCBOotsWireRoundTrip(t *testing.T) {
	in := &SVCBOots{Oots: []SVCBOotsEntry{
		{Proto: "do53", Weight: 100},
		{Proto: "dot", Weight: 5},
		{Proto: "doh", Weight: 10},
		{Proto: "doq", Weight: 5},
	}}
	b, err := in.pack()
	if err != nil {
		t.Fatalf("pack failed: %v", err)
	}
	if len(b) != in.len() {
		t.Fatalf("len() = %d, packed length = %d", in.len(), len(b))
	}
	out := new(SVCBOots)
	if err := out.unpack(b); err != nil {
		t.Fatalf("unpack failed: %v", err)
	}
	if !ootsEqual(in.Oots, out.Oots) {
		t.Fatalf("wire round-trip mismatch: got %v, want %v", out.Oots, in.Oots)
	}
}

// TestSVCBOotsPresentationRoundTrip exercises parse -> String for "oots".
func TestSVCBOotsPresentationRoundTrip(t *testing.T) {
	const want = "do53:100,dot:5,doq:5"
	e := new(SVCBOots)
	if err := e.parse(want); err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if got := e.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

// TestSVCBOotsWeightClamp checks that a wire weight octet greater than 100 is
// clamped to 100 on unpack, and that the entry/RR is not treated as malformed.
func TestSVCBOotsWeightClamp(t *testing.T) {
	// do53 with weight octet 200 (> 100) and dot with the max 255.
	wire := []byte{4, 'd', 'o', '5', '3', 200, 3, 'd', 'o', 't', 255}
	e := new(SVCBOots)
	if err := e.unpack(wire); err != nil {
		t.Fatalf("unpack rejected a >100 weight, must clamp instead: %v", err)
	}
	want := []SVCBOotsEntry{{Proto: "do53", Weight: 100}, {Proto: "dot", Weight: 100}}
	if !ootsEqual(e.Oots, want) {
		t.Fatalf("weight not clamped: got %v, want %v", e.Oots, want)
	}
}

// TestSVCBOotsDuplicateRejected checks that a duplicate protocol identifier is
// rejected as malformed by both unpack (wire) and parse (presentation).
func TestSVCBOotsDuplicateRejected(t *testing.T) {
	wire := []byte{4, 'd', 'o', '5', '3', 1, 4, 'd', 'o', '5', '3', 2}
	if err := new(SVCBOots).unpack(wire); err == nil {
		t.Error("unpack accepted a duplicate protocol identifier")
	}
	if err := new(SVCBOots).parse("do53:1,do53:2"); err == nil {
		t.Error("parse accepted a duplicate protocol identifier")
	}
}

// TestSVCBOotsUnknownSkipped checks that an unrecognized protocol identifier is
// ignored (not an error) while recognized entries are retained, on both the
// wire and presentation paths.
func TestSVCBOotsUnknownSkipped(t *testing.T) {
	// "xyz":9 (unknown) between do53:100 and doq:7 (both known).
	wire := []byte{4, 'd', 'o', '5', '3', 100, 3, 'x', 'y', 'z', 9, 3, 'd', 'o', 'q', 7}
	e := new(SVCBOots)
	if err := e.unpack(wire); err != nil {
		t.Fatalf("unpack failed on unknown proto: %v", err)
	}
	want := []SVCBOotsEntry{{Proto: "do53", Weight: 100}, {Proto: "doq", Weight: 7}}
	if !ootsEqual(e.Oots, want) {
		t.Fatalf("unknown proto not skipped on unpack: got %v, want %v", e.Oots, want)
	}

	p := new(SVCBOots)
	if err := p.parse("do53:100,xyz:9,doq:7"); err != nil {
		t.Fatalf("parse failed on unknown proto: %v", err)
	}
	if !ootsEqual(p.Oots, want) {
		t.Fatalf("unknown proto not skipped on parse: got %v, want %v", p.Oots, want)
	}
}

// TestSVCBOotsOrderInsensitive checks that entry order is accepted in any order
// and preserved as given (the draft states order is not significant).
func TestSVCBOotsOrderInsensitive(t *testing.T) {
	a := new(SVCBOots)
	if err := a.parse("dot:5,do53:100"); err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	wantA := []SVCBOotsEntry{{Proto: "dot", Weight: 5}, {Proto: "do53", Weight: 100}}
	if !ootsEqual(a.Oots, wantA) {
		t.Fatalf("order not preserved: got %v, want %v", a.Oots, wantA)
	}

	b := new(SVCBOots)
	if err := b.parse("do53:100,dot:5"); err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	wantB := []SVCBOotsEntry{{Proto: "do53", Weight: 100}, {Proto: "dot", Weight: 5}}
	if !ootsEqual(b.Oots, wantB) {
		t.Fatalf("order not preserved: got %v, want %v", b.Oots, wantB)
	}
}

// TestSVCBOotsParseErrors checks that malformed presentation entries are parse
// errors, and that an empty value is rejected.
func TestSVCBOotsParseErrors(t *testing.T) {
	bad := []string{
		"",             // no entries at all
		"do53",         // missing colon
		"do53:",        // missing weight
		"do53:x",       // non-decimal weight
		"do53:101",     // weight out of range (> 100)
		"do53:256",     // weight out of octet range
		":100",         // empty protocol identifier
		"do53:100,dot", // second entry missing colon
	}
	for _, in := range bad {
		if err := new(SVCBOots).parse(in); err == nil {
			t.Errorf("parse(%q) accepted a malformed value", in)
		}
	}
}

// TestSVCBOotsNewRR checks the full example from the draft round-trips through
// the zone-file parser and String().
func TestSVCBOotsNewRR(t *testing.T) {
	const zone = `ns.example.net. 300 IN SVCB 1 . oots="do53:100,dot:5,doq:5"`
	rr, err := NewRR(zone)
	if err != nil {
		t.Fatalf("NewRR failed: %v", err)
	}
	svcb, ok := rr.(*SVCB)
	if !ok {
		t.Fatalf("expected *SVCB, got %T", rr)
	}
	oots, ok := svcb.Value[0].(*SVCBOots)
	if !ok {
		t.Fatalf("expected *SVCBOots, got %T", svcb.Value[0])
	}
	want := []SVCBOotsEntry{
		{Proto: "do53", Weight: 100},
		{Proto: "dot", Weight: 5},
		{Proto: "doq", Weight: 5},
	}
	if !ootsEqual(oots.Oots, want) {
		t.Fatalf("parsed oots = %v, want %v", oots.Oots, want)
	}
	// The rendered RR must round-trip back through the parser unchanged.
	rr2, err := NewRR(rr.String())
	if err != nil {
		t.Fatalf("re-parsing rr.String() failed: %v", err)
	}
	if rr.String() != rr2.String() {
		t.Fatalf("String() not stable:\n %q\n %q", rr.String(), rr2.String())
	}
}

// TestSVCBOotsCopy checks that copy() produces an independent deep copy.
func TestSVCBOotsCopy(t *testing.T) {
	orig := &SVCBOots{Oots: []SVCBOotsEntry{{Proto: "do53", Weight: 100}}}
	cp, ok := orig.copy().(*SVCBOots)
	if !ok {
		t.Fatalf("copy() returned %T, want *SVCBOots", orig.copy())
	}
	cp.Oots[0].Weight = 1
	if orig.Oots[0].Weight != 100 {
		t.Fatal("copy() did not deep-copy the entry slice")
	}
}
