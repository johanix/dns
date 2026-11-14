package dns

import (
	"bytes"
	"net"
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

// TestSVCBOotsWeightRaw checks that a wire weight octet greater than 100 is
// kept as received by unpack and written back unchanged by pack, and that the
// entry/RR is not treated as malformed. Reading it as 100 is the consumer's job.
func TestSVCBOotsWeightRaw(t *testing.T) {
	// do53 with weight octet 200 (> 100) and dot with the max 255.
	wire := []byte{4, 'd', 'o', '5', '3', 200, 3, 'd', 'o', 't', 255}
	e := new(SVCBOots)
	if err := e.unpack(wire); err != nil {
		t.Fatalf("unpack rejected a >100 weight: %v", err)
	}
	want := []SVCBOotsEntry{{Proto: "do53", Weight: 200}, {Proto: "dot", Weight: 255}}
	if !ootsEqual(e.Oots, want) {
		t.Fatalf("weight not kept as received: got %v, want %v", e.Oots, want)
	}
	b, err := e.pack()
	if err != nil {
		t.Fatalf("pack failed: %v", err)
	}
	if !bytes.Equal(b, wire) {
		t.Fatalf("pack changed the weight octets: got %v, want %v", b, wire)
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

// TestSVCBOotsUnknownKept checks that an unrecognized protocol identifier is
// kept (not an error, not dropped) beside the recognized entries, in order, on
// both the wire and presentation paths.
func TestSVCBOotsUnknownKept(t *testing.T) {
	// "xyz":9 (unknown) between do53:100 and doq:7 (both known).
	wire := []byte{4, 'd', 'o', '5', '3', 100, 3, 'x', 'y', 'z', 9, 3, 'd', 'o', 'q', 7}
	e := new(SVCBOots)
	if err := e.unpack(wire); err != nil {
		t.Fatalf("unpack failed on unknown proto: %v", err)
	}
	want := []SVCBOotsEntry{{Proto: "do53", Weight: 100}, {Proto: "xyz", Weight: 9}, {Proto: "doq", Weight: 7}}
	if !ootsEqual(e.Oots, want) {
		t.Fatalf("unknown proto not kept on unpack: got %v, want %v", e.Oots, want)
	}

	p := new(SVCBOots)
	if err := p.parse("do53:100,xyz:9,doq:7"); err != nil {
		t.Fatalf("parse failed on unknown proto: %v", err)
	}
	if !ootsEqual(p.Oots, want) {
		t.Fatalf("unknown proto not kept on parse: got %v, want %v", p.Oots, want)
	}
}

// TestSVCBOotsLossless checks that the codec is lossless: text -> wire -> text
// and wire -> struct -> wire both give back the same bytes, for known tokens,
// unknown tokens mixed with known ones, and only unknown tokens.
func TestSVCBOotsLossless(t *testing.T) {
	tests := []struct {
		name string
		text string
		wire []byte
	}{
		{
			name: "known",
			text: "do53:100,dot:5,doq:5",
			wire: []byte{4, 'd', 'o', '5', '3', 100, 3, 'd', 'o', 't', 5, 3, 'd', 'o', 'q', 5},
		},
		{
			name: "mixed",
			text: "udp:100,dot:5,tcp:30,xyz:0",
			wire: []byte{3, 'u', 'd', 'p', 100, 3, 'd', 'o', 't', 5, 3, 't', 'c', 'p', 30, 3, 'x', 'y', 'z', 0},
		},
		{
			name: "only-unknown",
			text: "tcp:30",
			wire: []byte{3, 't', 'c', 'p', 30},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// text -> wire -> text
			p := new(SVCBOots)
			if err := p.parse(tc.text); err != nil {
				t.Fatalf("parse(%q): %v", tc.text, err)
			}
			b, err := p.pack()
			if err != nil {
				t.Fatalf("pack: %v", err)
			}
			if !bytes.Equal(b, tc.wire) {
				t.Fatalf("parse+pack = %v, want %v", b, tc.wire)
			}
			u := new(SVCBOots)
			if err := u.unpack(b); err != nil {
				t.Fatalf("unpack: %v", err)
			}
			if got := u.String(); got != tc.text {
				t.Fatalf("text -> wire -> text = %q, want %q", got, tc.text)
			}
			// wire -> struct -> wire
			w := new(SVCBOots)
			if err := w.unpack(tc.wire); err != nil {
				t.Fatalf("unpack: %v", err)
			}
			b2, err := w.pack()
			if err != nil {
				t.Fatalf("pack: %v", err)
			}
			if !bytes.Equal(b2, tc.wire) {
				t.Fatalf("wire -> struct -> wire = %v, want %v", b2, tc.wire)
			}
		})
	}
}

// TestSVCBOotsWeight150 checks a raw weight octet of 150: wire -> struct ->
// wire keeps it, and String shows it as received. Presentation-format parse
// still refuses a weight above 100, so that text does not parse back.
func TestSVCBOotsWeight150(t *testing.T) {
	wire := []byte{3, 'd', 'o', 't', 150, 3, 't', 'c', 'p', 30}
	e := new(SVCBOots)
	if err := e.unpack(wire); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	b, err := e.pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if !bytes.Equal(b, wire) {
		t.Fatalf("wire -> struct -> wire = %v, want %v", b, wire)
	}
	if got, want := e.String(), "dot:150,tcp:30"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if err := new(SVCBOots).parse(e.String()); err == nil {
		t.Fatal("parse accepted a weight above 100")
	}
}

// TestSVCBOotsRRLossless checks whole SVCB records: the presentation form
// survives NewRR -> PackRR -> UnpackRR -> String unchanged, and the wire form
// survives UnpackRR -> PackRR unchanged, including a record whose only oots
// entry is a token this codec does not know.
func TestSVCBOotsRRLossless(t *testing.T) {
	for _, zone := range []string{
		"_dns.foo.example.\t300\tIN\tSVCB\t1 . oots=\"do53:100,dot:5,doq:5\"",
		"_dns.foo.example.\t300\tIN\tSVCB\t1 . port=\"1234\" oots=\"do53:100,tcp:30,dot:5,xyz:9\"",
		"_dns.foo.example.\t300\tIN\tSVCB\t1 tcp-foo.example. oots=\"tcp:30\"",
	} {
		rr, err := NewRR(zone)
		if err != nil {
			t.Fatalf("NewRR(%q): %v", zone, err)
		}
		if rr.String() != zone {
			t.Fatalf("String() = %q, want %q", rr.String(), zone)
		}
		buf := make([]byte, Len(rr)+1)
		off, err := PackRR(rr, buf, 0, nil, false)
		if err != nil {
			t.Fatalf("PackRR(%q): %v", zone, err)
		}
		wire := buf[:off]
		rr2, _, err := UnpackRR(wire, 0)
		if err != nil {
			t.Fatalf("UnpackRR(%q): %v", zone, err)
		}
		if rr2.String() != zone {
			t.Fatalf("text -> wire -> text = %q, want %q", rr2.String(), zone)
		}
		buf2 := make([]byte, Len(rr2)+1)
		off2, err := PackRR(rr2, buf2, 0, nil, false)
		if err != nil {
			t.Fatalf("PackRR again(%q): %v", zone, err)
		}
		if !bytes.Equal(buf2[:off2], wire) {
			t.Fatalf("wire -> struct -> wire changed %q:\n got %v\nwant %v", zone, buf2[:off2], wire)
		}
	}
}

// TestSVCBOotsOnlyUnknownInMessage checks that a message carrying a record
// whose only oots entry is unknown to this codec unpacks, and packs again to
// the same bytes. Before the codec was lossless such a record re-packed as an
// empty value, which every decoder refuses, failing the whole message.
func TestSVCBOotsOnlyUnknownInMessage(t *testing.T) {
	rr, err := NewRR(`_dns.foo.example. 300 IN SVCB 1 tcp-foo.example. oots="tcp:30"`)
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	m := new(Msg)
	m.SetQuestion("foo.example.", TypeA)
	m.Response = true
	m.Answer = []RR{&A{Hdr: RR_Header{Name: "foo.example.", Rrtype: TypeA, Class: ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 1)}}
	m.Extra = []RR{rr}
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	m2 := new(Msg)
	if err := m2.Unpack(wire); err != nil {
		t.Fatalf("Unpack of a message with an only-unknown oots record: %v", err)
	}
	if len(m2.Answer) != 1 || len(m2.Extra) != 1 {
		t.Fatalf("got %d answers and %d additionals, want 1 and 1", len(m2.Answer), len(m2.Extra))
	}
	wire2, err := m2.Pack()
	if err != nil {
		t.Fatalf("Pack again: %v", err)
	}
	if !bytes.Equal(wire, wire2) {
		t.Fatal("message changed on unpack and pack")
	}
}

// TestSVCBOotsPackRefusesMalformed checks that pack never writes a value that
// every decoder would refuse: an empty value, or a duplicate identifier.
func TestSVCBOotsPackRefusesMalformed(t *testing.T) {
	if _, err := (&SVCBOots{}).pack(); err == nil {
		t.Error("pack wrote an empty value")
	}
	if _, err := (&SVCBOots{Oots: []SVCBOotsEntry{}}).pack(); err == nil {
		t.Error("pack wrote an empty value from an empty slice")
	}
	dup := &SVCBOots{Oots: []SVCBOotsEntry{{Proto: "tcp", Weight: 1}, {Proto: "tcp", Weight: 2}}}
	if _, err := dup.pack(); err == nil {
		t.Error("pack wrote a duplicate identifier")
	}
	if _, err := (&SVCBOots{Oots: []SVCBOotsEntry{{Proto: "", Weight: 1}}}).pack(); err == nil {
		t.Error("pack wrote an empty identifier")
	}
}

// TestSVCBOotsOddIdentifierRoundTrip checks that an identifier with bytes the
// presentation format has to escape (separators, backslash, quote, space,
// non-printable octets) survives wire -> text -> wire through a whole record.
func TestSVCBOotsOddIdentifierRoundTrip(t *testing.T) {
	protos := []string{"a,b", "x:y", `back\slash`, `q"uote`, "sp ace", "semi;colon", "\x00\x7f\xff", "tcp"}
	in := &SVCBOots{}
	for i, p := range protos {
		in.Oots = append(in.Oots, SVCBOotsEntry{Proto: p, Weight: uint8(i * 10)})
	}
	rr := &SVCB{
		Hdr:      RR_Header{Name: "_dns.foo.example.", Rrtype: TypeSVCB, Class: ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
		Value:    []SVCBKeyValue{in},
	}
	want, err := in.pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	rr2, err := NewRR(rr.String())
	if err != nil {
		t.Fatalf("NewRR(%q): %v", rr.String(), err)
	}
	got, err := rr2.(*SVCB).Value[0].pack()
	if err != nil {
		t.Fatalf("pack after parse: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire -> text -> wire changed the value via %q:\n got %v\nwant %v", rr.String(), got, want)
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
		"",                // no entries at all
		"do53",            // missing colon
		"do53:",           // missing weight
		"do53:x",          // non-decimal weight
		"do53:101",        // weight out of range (> 100)
		"do53:256",        // weight out of octet range
		":100",            // empty protocol identifier
		"do53:100,dot",    // second entry missing colon
		"do53:100,,dot:5", // empty entry in the middle
		",do53:100",       // empty first entry
		"do53:1:2",        // second colon in the weight
		`a\\q:1`,          // value-list escape of a byte that needs none
		`a\\`,             // unterminated value-list escape
		`do53:1\\,`,       // value-list escape inside the weight
		"tcp:150",         // a raw weight above 100 is not valid text
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

// TestSVCBOotsTrailingComma checks that a single trailing comma is still
// accepted, as it was before the codec became lossless.
func TestSVCBOotsTrailingComma(t *testing.T) {
	e := new(SVCBOots)
	if err := e.parse("do53:100,tcp:30,"); err != nil {
		t.Fatalf("parse refused a trailing comma: %v", err)
	}
	want := []SVCBOotsEntry{{Proto: "do53", Weight: 100}, {Proto: "tcp", Weight: 30}}
	if !ootsEqual(e.Oots, want) {
		t.Fatalf("got %v, want %v", e.Oots, want)
	}
}
