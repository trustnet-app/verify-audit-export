package auditspec

import (
	"encoding/json"
	"fmt"
	"time"
)

// Envelope is the leaf payload (spec §4): the fields whose JCS canonical form
// is hashed with the RFC 6962 leaf prefix. The JSON names must match the spec
// exactly.
type Envelope struct {
	V        int             `json:"v"`
	Tree     string          `json:"tree"`
	Seq      int64           `json:"seq"`
	EventID  string          `json:"event_id"`
	TS       time.Time       `json:"ts"`
	Type     string          `json:"type"`
	Actor    json.RawMessage `json:"actor"`
	Producer json.RawMessage `json:"producer"`
	PPID     *string         `json:"ppid"`
	Payload  json.RawMessage `json:"payload"`
}

// canonicalBytes returns the RFC 8785 canonical serialization of the envelope.
// TS is normalized to UTC first so the leaf hash is zone-independent.
func (e Envelope) canonicalBytes() ([]byte, error) {
	e.TS = e.TS.UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal envelope: %w", err)
	}
	return CanonicalJSON(b)
}

// CanonicalBytes is the exported form of canonicalBytes — the byte string the
// leaf hash covers.
func (e Envelope) CanonicalBytes() ([]byte, error) {
	return e.canonicalBytes()
}
