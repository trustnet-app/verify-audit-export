package verify

// jws_test.go — the hand-rolled EdDSA compact JWS (RFC 7515 §7.2.2 /
// RFC 8037): round-trip through the fixture signer, then one mutation per
// link (signature, payload, key id, algorithm, serialization shape) that
// verifyJWS must catch.

import (
	"encoding/json"
	"strings"
	"testing"

	audit "github.com/trustnet-app/verify-audit-export/internal/auditspec"
)

func testKeys(t *testing.T, s *memSigner) []audit.KeyRecord {
	t.Helper()
	return []audit.KeyRecord{{
		KeyID:     s.kid,
		PublicKey: pemPublicKey(t, s.pub),
		Algorithm: "Ed25519",
		Status:    audit.KeyStatusActive,
	}}
}

func TestVerifyJWSRoundTrip(t *testing.T) {
	s := newMemSigner("audit-key:v7")
	payload := []byte(`{"bundle_version":"trustnet-rp-export.v1","tree":"rp:demo"}`)
	jws := signJWS(t, s, payload)

	if parts := strings.Split(jws, "."); len(parts) != 3 {
		t.Fatalf("jws has %d segments, want 3: %q", len(parts), jws)
	}

	got, kid, err := verifyJWS(jws, testKeys(t, s))
	if err != nil {
		t.Fatalf("verifyJWS: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if kid != s.kid {
		t.Errorf("kid = %q, want %q", kid, s.kid)
	}

	// The header names the key and the signature covers the header: the
	// payload alone round-trips, but every other segment is integrity-bound.
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := b64urlDecode(strings.Split(jws, ".")[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if hdr.Alg != "EdDSA" || hdr.Kid != s.kid {
		t.Errorf("header = %+v, want EdDSA kid %q", hdr, s.kid)
	}
}

func TestVerifyJWSCatchesMutations(t *testing.T) {
	s := newMemSigner("audit-key:v7")
	payload := []byte(`{"tree":"rp:demo","events":3}`)
	jws := signJWS(t, s, payload)
	keys := testKeys(t, s)
	parts := strings.Split(jws, ".")

	rewrite := func(mut func(p []string) []string) string {
		cp := append([]string(nil), parts...)
		return strings.Join(mut(cp), ".")
	}

	t.Run("corrupt signature", func(t *testing.T) {
		mutated := rewrite(func(p []string) []string {
			p[2] = b64url([]byte("forged"))
			return p
		})
		if _, _, err := verifyJWS(mutated, keys); err == nil || !strings.Contains(err.Error(), "signature does not verify") {
			t.Fatalf("err = %v, want signature failure", err)
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		mutated := rewrite(func(p []string) []string {
			p[1] = b64url([]byte(`{"tree":"rp:evil","events":3}`))
			return p
		})
		if _, _, err := verifyJWS(mutated, keys); err == nil || !strings.Contains(err.Error(), "signature does not verify") {
			t.Fatalf("err = %v, want signature failure", err)
		}
	})

	t.Run("unknown key id", func(t *testing.T) {
		mutated := rewrite(func(p []string) []string {
			var h map[string]string
			if err := json.Unmarshal(mustB64(p[0]), &h); err != nil {
				t.Fatalf("decode header: %v", err)
			}
			h["kid"] = "ghost-key"
			hb, _ := json.Marshal(h)
			p[0] = b64url(hb)
			return p
		})
		if _, _, err := verifyJWS(mutated, keys); err == nil || !strings.Contains(err.Error(), "kid") {
			t.Fatalf("err = %v, want unknown kid", err)
		}
	})

	t.Run("wrong algorithm", func(t *testing.T) {
		mutated := rewrite(func(p []string) []string {
			var h map[string]string
			if err := json.Unmarshal(mustB64(p[0]), &h); err != nil {
				t.Fatalf("decode header: %v", err)
			}
			h["alg"] = "RS256"
			hb, _ := json.Marshal(h)
			p[0] = b64url(hb)
			return p
		})
		if _, _, err := verifyJWS(mutated, keys); err == nil || !strings.Contains(err.Error(), `alg "RS256", want EdDSA`) {
			t.Fatalf("err = %v, want alg rejection", err)
		}
	})

	t.Run("malformed serialization", func(t *testing.T) {
		for _, bad := range []string{"", "a.b", "a.b.c.d", "not-a-jws"} {
			if _, _, err := verifyJWS(bad, keys); err == nil {
				t.Fatalf("verifyJWS(%q) succeeded", bad)
			}
		}
	})

	t.Run("signature by another key", func(t *testing.T) {
		other := newMemSigner("other-key:v1")
		jwsOther := signJWS(t, other, payload)
		if _, _, err := verifyJWS(jwsOther, keys); err == nil || !strings.Contains(err.Error(), "kid") {
			t.Fatalf("err = %v, want unknown kid for a foreign key", err)
		}
	})

	t.Run("key record without pem", func(t *testing.T) {
		keysBad := []audit.KeyRecord{{KeyID: s.kid, PublicKey: "not pem", Algorithm: "Ed25519"}}
		if _, _, err := verifyJWS(jws, keysBad); err == nil || !strings.Contains(err.Error(), "no PEM block") {
			t.Fatalf("err = %v, want PEM rejection", err)
		}
	})
}

func mustB64(s string) []byte {
	b, err := b64urlDecode(s)
	if err != nil {
		panic(err)
	}
	return b
}
