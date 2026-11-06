// Package verify is the offline verifier for TrustNet audit export bundles
// (spec §10.1). It answers the canonical auditor question against a
// self-contained tar.gz — manifest JWS, events, proofs, anchors, keys — with
// no service, database, or network access.
//
// The bundle's manifest is a compact EdDSA JWS (RFC 7515 §7.2.2 / RFC 8037);
// this package only verifies it.
package verify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	audit "github.com/trustnet-app/verify-audit-export/internal/auditspec"
)

// jwsHeader is the JWS protected header: EdDSA (RFC 8037) with the key id.
// The kid names the audit key that signed, so a swapped key id is a
// signature failure, not metadata — the signature covers the header.
type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// b64url is raw URL-safe base64 without padding (RFC 7515 §5.1); kept for the
// test corpus that reconstructs signatures by hand.
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// b64urlDecode is raw URL-safe base64 without padding (RFC 7515 §5.1).
func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// VerifyJWS verifies a compact JWS against the key history: the kid must
// resolve to an Ed25519 SPKI PEM key and the signature must verify. It
// returns the signed payload and the kid that verified.
func VerifyJWS(jws string, keys []audit.KeyRecord) (payload []byte, kid string, err error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, "", errors.New("export: jws: malformed compact serialization")
	}
	hb, err := b64urlDecode(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("export: jws: header: %w", err)
	}
	var h jwsHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, "", fmt.Errorf("export: jws: header: %w", err)
	}
	if h.Alg != "EdDSA" {
		return nil, "", fmt.Errorf("export: jws: alg %q, want EdDSA", h.Alg)
	}
	pub, err := resolvePublicKey(h.Kid, keys)
	if err != nil {
		return nil, "", err
	}
	sig, err := b64urlDecode(parts[2])
	if err != nil {
		return nil, "", fmt.Errorf("export: jws: signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, "", errors.New("export: jws: signature does not verify")
	}
	payload, err = b64urlDecode(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("export: jws: payload: %w", err)
	}
	return payload, h.Kid, nil
}

// resolvePublicKey finds the key record for kid and parses its SPKI PEM into
// an Ed25519 public key.
func resolvePublicKey(kid string, keys []audit.KeyRecord) (ed25519.PublicKey, error) {
	for _, k := range keys {
		if k.KeyID != kid {
			continue
		}
		block, _ := pem.Decode([]byte(k.PublicKey))
		if block == nil {
			return nil, fmt.Errorf("export: jws: key %q: no PEM block", kid)
		}
		pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("export: jws: key %q: %w", kid, err)
		}
		pub, ok := pubAny.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("export: jws: key %q is %T, want ed25519", kid, pubAny)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("export: jws: kid %q not found in keys.json", kid)
}
