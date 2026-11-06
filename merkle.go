package verify

import (
	audit "github.com/trustnet-app/verify-audit-export/internal/auditspec"
)

// mth is the RFC 6962 MTH over leaves[l:r] (leaves are already
// domain-separated leaf hashes, so the leaf-level value is leaves[i]
// itself). It mirrors internal/audit/meta.go's mth — the same algorithm the
// audit trees and the meta-tree are built with, so the verifier's range
// recomputation agrees with the signed STH root. The full-range v1 proof is
// degenerate: the range check IS recomputing this root from the bundle's
// leaves and comparing it to the STH root (deviation recorded in log.md).
func mth(leaves [][]byte, l, r int) []byte {
	if r-l == 1 {
		return leaves[l]
	}
	k := largestPowerOfTwoLessThan(r - l)
	return audit.HashChildren(mth(leaves, l, l+k), mth(leaves, l+k, r))
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less
// than n (the RFC 6962 split point for a span of n leaves).
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}
