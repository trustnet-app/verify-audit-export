package verify

import (
	"encoding/json"
	"time"

	audit "github.com/trustnet-app/verify-audit-export/internal/auditspec"
)

// Bundle versions the verifier understands (spec §10.1/§10.2,
// auth-events.md §9).
const (
	BundleVersionRP   = "trustnet-rp-export.v1"
	BundleVersionUser = "trustnet-user-export.v2"
	BundleVersionAuth = "trustnet-auth-export.v1"
)

// ManifestPayload is the signed manifest payload of a bundle. Files maps each
// archived file (except manifest.json itself — a manifest cannot digest
// itself) to the hex SHA-256 of its contents, so the JWS binds every file in
// the archive.
//
// This is the verifier-side definition of the wire shape; it mirrors the
// producer's struct in trustnet_ory and must stay compatible with the same
// spec version.
type ManifestPayload struct {
	BundleVersion string            `json:"bundle_version"`
	Tree          string            `json:"tree"`
	Range         audit.ExportRange `json:"range"`
	EventCount    int64             `json:"event_count"`
	Files         map[string]string `json:"files"`
	KeyID         string            `json:"key_id"`
	GeneratedAt   time.Time         `json:"generated_at"`
}

// sthFilePayload is proofs/sth.json: the STH's canonical JSON bytes verbatim
// (the exact bytes the signature covers) plus the signature.
type sthFilePayload struct {
	STH       json.RawMessage `json:"sth"`
	Signature []byte          `json:"signature"`
}

// rangeFilePayload is proofs/range.json. For the full-range v1 the range
// proof is degenerate: root_hash is the recomputed RFC 6962 root over every
// leaf, and the verifier's range check is comparing it to the STH root.
type rangeFilePayload struct {
	FromSeq   int64  `json:"from_seq"`
	ToSeq     int64  `json:"to_seq"`
	LeafCount int64  `json:"leaf_count"`
	RootHash  []byte `json:"root_hash"`
}

// consistencyFilePayload is proofs/consistency.json: the RFC 6962 consistency
// proof from an older head to the export head.
type consistencyFilePayload struct {
	PrevSize uint64   `json:"prev_size"`
	PrevRoot []byte   `json:"prev_root"`
	Size     uint64   `json:"size"`
	Root     []byte   `json:"root"`
	Proof    [][]byte `json:"proof"`
}

// anchorFilePayload is anchors/YYYY-MM-DD.json: one meta-tree anchor with the
// per-tree evidence the verifier needs for this tree's inclusion.
type anchorFilePayload struct {
	AnchorTime    time.Time       `json:"anchor_time"`
	MetaRoot      []byte          `json:"meta_root"`
	TSAToken      []byte          `json:"tsa_token,omitempty"`
	SelfSignature []byte          `json:"self_signature,omitempty"`
	SelfKeyID     *string         `json:"self_key_id,omitempty"`
	TSAIdentity   json.RawMessage `json:"tsa_identity"`
	Clock         json.RawMessage `json:"clock"`
	ThisTree      anchorTreeFile  `json:"this_tree"`
}

// anchorTreeFile is the this_tree member: the anchored STH (canonical bytes
// verbatim) with its signature, plus the inclusion proof and its position in
// the meta-tree leaf order.
type anchorTreeFile struct {
	Tree           string          `json:"tree"`
	STH            json.RawMessage `json:"sth"`
	STHSignature   []byte          `json:"sth_signature"`
	InclusionProof [][]byte        `json:"inclusion_proof"`
	Index          int             `json:"index"`
	TreeCount      int             `json:"tree_count"`
}
