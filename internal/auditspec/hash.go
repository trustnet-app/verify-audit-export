// Package auditspec is the verifier-side copy of the audit wire format: the
// JCS-canonicalized
// v2 envelope (RFC 8785), its RFC 6962 Merkle leaf hash, the append-only
// per-tree writer (spec §7), proof materialization and the rebuild repair.
// The SQL lives in internal/audit/store; this package holds the domain rules.
package auditspec

import (
	"github.com/transparency-dev/merkle/rfc6962"
)

// hasher is the single hash function of the audit trees: SHA-256 with RFC
// 6962 domain separation (0x00 for leaves, 0x01 for interior nodes, empty
// root = SHA-256 of the empty string).
var hasher = rfc6962.DefaultHasher

// EmptyRoot is the root hash of the empty tree (RFC 6962): SHA-256("").
var EmptyRoot = hasher.EmptyRoot()

// HashLeaf returns the leaf hash of a canonical envelope:
// SHA-256(0x00 || leaf).
func HashLeaf(leaf []byte) []byte {
	return hasher.HashLeaf(leaf)
}

// HashChildren returns the interior node hash:
// SHA-256(0x01 || left || right).
func HashChildren(left, right []byte) []byte {
	return hasher.HashChildren(left, right)
}
