package auditspec

import (
	"fmt"
	"strings"
)

// Tree state for the suspension invariant (spec §5 semantics 5).
type treeState int

const (
	stateNormal treeState = iota
	stateSuspended
	stateDeleted
)

// CheckSuspensionInvariant validates spec §5 semantics 5 over an ordered
// event-type sequence:
//
//   - after rp.suspended until rp.reinstated, only revocation.*, erasure.*,
//     export.generated, rp.reinstated and rp.deleted may be appended;
//   - after rp.deleted, only export.generated may be appended.
//
// Literal reading (pinned in log.md M2.4.3): consent.revoked is NOT the
// revocation.* family — the taxonomy names the bulk revocation events
// revocation.effected, so a consent.revoked during a suspension is flagged.
func CheckSuspensionInvariant(types []string) error {
	state := stateNormal
	for i, t := range types {
		switch state {
		case stateNormal:
			switch t {
			case TypeRPSuspended:
				state = stateSuspended
			case TypeRPDeleted:
				state = stateDeleted
			}
		case stateSuspended:
			if allowedDuringSuspension(t) {
				switch t {
				case TypeRPReinstated:
					state = stateNormal
				case TypeRPDeleted:
					state = stateDeleted
				}
				continue
			}
			return fmt.Errorf("audit: invariant violation at %d: event %q is not allowed while the RP is suspended (spec §5 semantics 5)", i, t)
		case stateDeleted:
			if t != TypeExportGenerated {
				return fmt.Errorf("audit: invariant violation at %d: event %q is not allowed after rp.deleted (spec §5 semantics 5)", i, t)
			}
		}
	}
	return nil
}

// allowedDuringSuspension reports whether a type may appear between
// rp.suspended and rp.reinstated/rp.deleted. The prefix families are the
// spec's revocation.* and erasure.*.
func allowedDuringSuspension(t string) bool {
	switch {
	case strings.HasPrefix(t, "revocation."),
		strings.HasPrefix(t, "erasure."),
		t == TypeExportGenerated,
		t == TypeRPReinstated,
		t == TypeRPDeleted:
		return true
	}
	return false
}
