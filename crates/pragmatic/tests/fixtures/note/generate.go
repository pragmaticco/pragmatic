// Command generate writes vectors.json, the signed-note, tlog-checkpoint and
// cosignature/v1 test vectors used by crates/pragmatic/src/note.rs.
//
// It uses only the Go standard library, so the signatures come from Go's
// crypto/ed25519 rather than from the Rust code under test, and the key IDs,
// verifier keys and signed messages are built here directly from the C2SP
// specifications:
//
//   - https://github.com/C2SP/C2SP/blob/main/signed-note.md
//   - https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md
//   - https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md
//
// Ed25519 signatures are deterministic and every key is derived from a fixed
// seed, so the output is identical on every run:
//
//	go run generate.go > vectors.json
//
// The seeds are public. These keys sign nothing but test fixtures.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	algEd25519       = 0x01
	algCosignatureV1 = 0x04
)

type key struct {
	label string
	name  string
	alg   byte
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

func newKey(label, name string, alg byte) *key {
	seed := sha256.Sum256([]byte("pragmatic signed-note fixture: " + label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return &key{label: label, name: name, alg: alg, priv: priv, pub: priv.Public().(ed25519.PublicKey)}
}

// keyID is SHA-256(name || 0x0A || type || public key)[:4].
func (k *key) keyID() []byte {
	h := sha256.New()
	h.Write([]byte(k.name))
	h.Write([]byte{0x0a, k.alg})
	h.Write(k.pub)
	return h.Sum(nil)[:4]
}

// vkey is <name>+hex(key ID)+base64(type || public key).
func (k *key) vkey() string {
	return k.name + "+" + hex.EncodeToString(k.keyID()) + "+" +
		base64.StdEncoding.EncodeToString(append([]byte{k.alg}, k.pub...))
}

// line formats a signature line: em dash, space, name, space, base64(key ID || sig).
func line(name string, keyID, sig []byte) string {
	return "— " + name + " " + base64.StdEncoding.EncodeToString(append(append([]byte{}, keyID...), sig...)) + "\n"
}

// sign returns the signature line for body: a plain Ed25519 note signature
// for type 0x01, or a timestamped cosignature/v1 for type 0x04.
func (k *key) sign(body string, timestamp uint64) string {
	switch k.alg {
	case algEd25519:
		return line(k.name, k.keyID(), ed25519.Sign(k.priv, []byte(body)))
	case algCosignatureV1:
		msg := cosignatureMessage(timestamp, body)
		sig := binary.BigEndian.AppendUint64(nil, timestamp)
		sig = append(sig, ed25519.Sign(k.priv, msg)...)
		return line(k.name, k.keyID(), sig)
	}
	panic("unknown algorithm")
}

func cosignatureMessage(timestamp uint64, body string) []byte {
	return []byte("cosignature/v1\ntime " + strconv.FormatUint(timestamp, 10) + "\n" + body)
}

func checkpointBody(origin string, size uint64, root []byte, extensions ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root))
	for _, e := range extensions {
		b.WriteString(e + "\n")
	}
	return b.String()
}

func fakeRoot(label string) []byte {
	h := sha256.Sum256([]byte(label))
	return h[:]
}

type checkpoint struct {
	Origin     string   `json:"origin"`
	TreeSize   uint64   `json:"tree_size"`
	Root       string   `json:"root"`
	Extensions []string `json:"extensions"`
}

type verified struct {
	Key       string  `json:"key"`
	Signature int     `json:"signature"`
	Timestamp *uint64 `json:"timestamp"`
}

type testCase struct {
	Name       string      `json:"name"`
	Note       string      `json:"note"`
	Checkpoint *checkpoint `json:"checkpoint"`
	Trusted    []string    `json:"trusted"`
	Result     string      `json:"result"`
	Verified   []verified  `json:"verified"`
}

type keyEntry struct {
	Label     string `json:"label"`
	Name      string `json:"name"`
	Type      int    `json:"type"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Vkey      string `json:"vkey"`
}

type output struct {
	Comment []string   `json:"comment"`
	Keys    []keyEntry `json:"keys"`
	Cases   []testCase `json:"cases"`
}

func ts(v uint64) *uint64 { return &v }

func main() {
	log := newKey("log", "pragmatic/example", algEd25519)
	w1 := newKey("witness1", "witness.example/one", algCosignatureV1)
	w2 := newKey("witness2", "witness.example/two", algCosignatureV1)
	other := newKey("other", "other.example/log", algEd25519)
	// The first witness's public key and name, but as a plain Ed25519 note
	// key (type 0x01), which has a different key ID.
	w1plain := &key{label: "witness1-plain", name: w1.name, alg: algEd25519, priv: w1.priv, pub: w1.pub}
	keys := []*key{log, w1, w2, other, w1plain}

	const t1, t2 = 1760000000, 1760000123

	body42 := checkpointBody("pragmatic/example", 42, fakeRoot("root 42"))
	cp42 := &checkpoint{"pragmatic/example", 42, base64.StdEncoding.EncodeToString(fakeRoot("root 42")), []string{}}
	body43 := checkpointBody("pragmatic/example", 43, fakeRoot("root 43"))
	bodyExt := checkpointBody("pragmatic/example", 7, fakeRoot("root 7"), "extension one", "x+y=z")
	cpExt := &checkpoint{"pragmatic/example", 7, base64.StdEncoding.EncodeToString(fakeRoot("root 7")), []string{"extension one", "x+y=z"}}
	empty := sha256.Sum256(nil)
	bodyEmpty := checkpointBody("pragmatic/example", 0, empty[:])
	cpEmpty := &checkpoint{"pragmatic/example", 0, base64.StdEncoding.EncodeToString(empty[:]), []string{}}
	plain := "A note that is not a checkpoint.\n\nIts text has an empty line, and only the last one separates the signatures.\n"

	cosigned := body42 + "\n" + log.sign(body42, 0) + w1.sign(body42, t1) + w2.sign(body42, t2)

	// One flipped bit in the last signature byte.
	tamper := func(l string) string {
		fields := strings.SplitN(strings.TrimSuffix(l, "\n"), " ", 3)
		raw, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			panic(err)
		}
		raw[len(raw)-1] ^= 0x01
		return fields[0] + " " + fields[1] + " " + base64.StdEncoding.EncodeToString(raw) + "\n"
	}
	// A cosignature whose timestamp field says t1+1 while the signature
	// covers t1.
	wrongTime := func() string {
		l := w1.sign(body42, t1)
		fields := strings.SplitN(strings.TrimSuffix(l, "\n"), " ", 3)
		raw, _ := base64.StdEncoding.DecodeString(fields[2])
		binary.BigEndian.PutUint64(raw[4:12], t1+1)
		return fields[0] + " " + fields[1] + " " + base64.StdEncoding.EncodeToString(raw) + "\n"
	}()
	// The log's name and key ID on a signature made by another key.
	impostor := line(log.name, log.keyID(), ed25519.Sign(other.priv, []byte(body42)))

	cases := []testCase{
		{
			Name: "log signature", Note: body42 + "\n" + log.sign(body42, 0), Checkpoint: cp42,
			Trusted: []string{"log"}, Result: "ok",
			Verified: []verified{{"log", 0, nil}},
		},
		{
			Name: "log signature and two witness cosignatures", Note: cosigned, Checkpoint: cp42,
			Trusted: []string{"log", "witness1", "witness2"}, Result: "ok",
			Verified: []verified{{"log", 0, nil}, {"witness1", 1, ts(t1)}, {"witness2", 2, ts(t2)}},
		},
		{
			Name: "only the second witness trusted", Note: cosigned, Checkpoint: cp42,
			Trusted: []string{"witness2"}, Result: "ok",
			Verified: []verified{{"witness2", 2, ts(t2)}},
		},
		{
			Name: "no trusted keys", Note: cosigned, Checkpoint: cp42,
			Trusted: []string{}, Result: "no_verified_signature",
		},
		{
			Name: "unknown signer is ignored", Note: body42 + "\n" + other.sign(body42, 0) + log.sign(body42, 0), Checkpoint: cp42,
			Trusted: []string{"log"}, Result: "ok",
			Verified: []verified{{"log", 1, nil}},
		},
		{
			Name: "tampered log signature", Note: body42 + "\n" + tamper(log.sign(body42, 0)), Checkpoint: cp42,
			Trusted: []string{"log"}, Result: "invalid_signature",
		},
		{
			Name: "tampered log signature from an untrusted key is ignored", Note: body42 + "\n" + tamper(log.sign(body42, 0)) + w1.sign(body42, t1), Checkpoint: cp42,
			Trusted: []string{"witness1"}, Result: "ok",
			Verified: []verified{{"witness1", 1, ts(t1)}},
		},
		{
			Name: "cosignature timestamp altered", Note: body42 + "\n" + log.sign(body42, 0) + wrongTime, Checkpoint: cp42,
			Trusted: []string{"log", "witness1"}, Result: "invalid_signature",
		},
		{
			Name: "cosigner key configured as a plain Ed25519 key", Note: cosigned, Checkpoint: cp42,
			Trusted: []string{"witness1-plain"}, Result: "no_verified_signature",
		},
		{
			Name: "log name and key ID on another key's signature", Note: body42 + "\n" + impostor, Checkpoint: cp42,
			Trusted: []string{"log"}, Result: "invalid_signature",
		},
		{
			Name: "cosignature over a different checkpoint", Note: body42 + "\n" + log.sign(body42, 0) + w1.sign(body43, t1), Checkpoint: cp42,
			Trusted: []string{"log", "witness1"}, Result: "invalid_signature",
		},
		{
			Name: "extension lines are signed and cosigned", Note: bodyExt + "\n" + log.sign(bodyExt, 0) + w1.sign(bodyExt, t1), Checkpoint: cpExt,
			Trusted: []string{"log", "witness1"}, Result: "ok",
			Verified: []verified{{"log", 0, nil}, {"witness1", 1, ts(t1)}},
		},
		{
			Name: "empty tree", Note: bodyEmpty + "\n" + log.sign(bodyEmpty, 0), Checkpoint: cpEmpty,
			Trusted: []string{"log"}, Result: "ok",
			Verified: []verified{{"log", 0, nil}},
		},
		{
			Name: "repeated signature line is reported once", Note: body42 + "\n" + log.sign(body42, 0) + log.sign(body42, 0), Checkpoint: cp42,
			Trusted: []string{"log"}, Result: "ok",
			Verified: []verified{{"log", 0, nil}},
		},
		{
			Name: "repeated cosignature line is reported once", Note: body42 + "\n" + w1.sign(body42, t1) + log.sign(body42, 0) + w1.sign(body42, t1), Checkpoint: cp42,
			Trusted: []string{"log", "witness1"}, Result: "ok",
			Verified: []verified{{"witness1", 0, ts(t1)}, {"log", 1, nil}},
		},
		// Two valid cosignatures from one witness with different times:
		// tlog-checkpoint forbids two lines with the same key name and key
		// ID, and accepting them would let the line order pick the time.
		{
			Name: "two different cosignatures from one witness", Note: body42 + "\n" + log.sign(body42, 0) + w1.sign(body42, t2) + w1.sign(body42, t1), Checkpoint: cp42,
			Trusted: []string{"log", "witness1"}, Result: "repeated_key",
		},
		{
			Name: "the same two cosignatures in the other order", Note: body42 + "\n" + log.sign(body42, 0) + w1.sign(body42, t1) + w1.sign(body42, t2), Checkpoint: cp42,
			Trusted: []string{"witness1"}, Result: "repeated_key",
		},
		{
			Name: "two different cosignatures from an untrusted witness are ignored", Note: body42 + "\n" + log.sign(body42, 0) + w1.sign(body42, t1) + w1.sign(body42, t2), Checkpoint: cp42,
			Trusted: []string{"log"}, Result: "ok",
			Verified: []verified{{"log", 0, nil}},
		},
		{
			Name: "note text that is not a checkpoint", Note: plain + "\n" + log.sign(plain, 0), Checkpoint: nil,
			Trusted: []string{"log"}, Result: "ok",
			Verified: []verified{{"log", 0, nil}},
		},
	}

	// Self-check every signature line from a trusted key against Go's
	// verifier before writing, so a generator bug cannot produce vectors
	// that agree with a matching bug in the code under test. Lines are
	// checked in order and the first failure decides the result.
	byLabel := map[string]*key{}
	for _, k := range keys {
		byLabel[k.label] = k
	}
	for _, c := range cases {
		// The text ends at the last blank line; signature lines follow.
		idx := strings.LastIndex(c.Note, "\n\n")
		body := c.Note[:idx+1]
		first := map[string]string{} // trusted label -> its first verified line
		want := ""
	lines:
		for _, l := range strings.Split(strings.TrimSuffix(c.Note[idx+2:], "\n"), "\n") {
			fields := strings.SplitN(l, " ", 3)
			raw, err := base64.StdEncoding.DecodeString(fields[2])
			if err != nil {
				panic(err)
			}
			for _, label := range c.Trusted {
				k := byLabel[label]
				if k.name != fields[1] || !bytes.Equal(k.keyID(), raw[:4]) {
					continue
				}
				var okSig bool
				switch k.alg {
				case algEd25519:
					okSig = ed25519.Verify(k.pub, []byte(body), raw[4:])
				case algCosignatureV1:
					okSig = len(raw) == 4+8+64 &&
						ed25519.Verify(k.pub, cosignatureMessage(binary.BigEndian.Uint64(raw[4:12]), body), raw[12:])
				}
				if !okSig {
					want = "invalid_signature"
					break lines
				}
				if prev, seen := first[label]; seen && prev != l {
					want = "repeated_key"
					break lines
				} else if !seen {
					first[label] = l
				}
			}
		}
		if want == "" && len(first) == 0 {
			want = "no_verified_signature"
		} else if want == "" {
			want = "ok"
		}
		if want != c.Result {
			fmt.Fprintf(os.Stderr, "case %q: Go verification says %s, vector says %s\n", c.Name, want, c.Result)
			os.Exit(1)
		}
	}

	out := output{
		Comment: []string{
			"Generated by generate.go (go run generate.go > vectors.json); do not edit.",
			"Signatures are from Go's crypto/ed25519. Keys derive from public seeds and sign only test data.",
			"result: ok (verified lists each trusted key that verified, once, with the index of its first signature line),",
			"invalid_signature (a trusted key's signature failed), repeated_key (a trusted key signed two different lines)",
			"or no_verified_signature (no trusted key signed).",
		},
	}
	for _, k := range keys {
		out.Keys = append(out.Keys, keyEntry{
			Label: k.label, Name: k.name, Type: int(k.alg),
			KeyID: hex.EncodeToString(k.keyID()), PublicKey: hex.EncodeToString(k.pub), Vkey: k.vkey(),
		})
	}
	for i := range cases {
		if cases[i].Verified == nil {
			cases[i].Verified = []verified{}
		}
	}
	out.Cases = cases

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
