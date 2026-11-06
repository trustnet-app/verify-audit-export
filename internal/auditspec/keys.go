package auditspec

import "time"

// Key statuses derived from the audit_key.* event chain (spec §10.1).
const (
	KeyStatusActive  = "active"
	KeyStatusRotated = "rotated"
	KeyStatusRevoked = "revoked"
)

// KeyRecord is one entry of the published key history (spec §10.1 keys.json).
type KeyRecord struct {
	KeyID     string    `json:"key_id"`
	PublicKey string    `json:"public_key"`
	Algorithm string    `json:"algorithm"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
