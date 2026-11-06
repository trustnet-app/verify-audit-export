package auditspec

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Clock is the STH's `clock` telemetry (spec §8). Self-reported and
// corroborating only — probative time comes from TSA anchors.
type Clock struct {
	Source     string `json:"source"`
	OffsetMS   int    `json:"offset_ms"`
	SyncStatus string `json:"sync_status"`
}

// STH is the signed tree head (spec §8). The canonical JSON form of exactly
// this object is what gets signed — key_id included, so the head names its own
// verifying key and a swapped id is a signature failure, not metadata.
type STH struct {
	V        int          `json:"v"`
	Tree     string       `json:"tree"`
	TreeSize uint64       `json:"tree_size"`
	RootHash []byte       `json:"root_hash"`
	STHTime  time.Time    `json:"sth_time"`
	KeyID    string       `json:"key_id"`
	Producer ProducerInfo `json:"producer"`
	Clock    Clock        `json:"clock"`
}

// canonicalBytes returns the RFC 8785 canonical serialization of the STH —
// the byte string the signature covers. STHTime is normalized to UTC first so
// the signed bytes are zone-independent.
func (s STH) canonicalBytes() ([]byte, error) {
	s.STHTime = s.STHTime.UTC()
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal sth: %w", err)
	}
	return CanonicalJSON(b)
}

// CanonicalBytes is the exported form of canonicalBytes.
func (s STH) CanonicalBytes() ([]byte, error) {
	return s.canonicalBytes()
}

// VerifySTH checks an Ed25519 signature over the STH's canonical bytes.
func VerifySTH(s STH, sig []byte, pub ed25519.PublicKey) error {
	canon, err := s.canonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canon, sig) {
		return errors.New("audit: sth signature does not verify")
	}
	return nil
}
