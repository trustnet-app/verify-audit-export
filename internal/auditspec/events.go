// Event taxonomy (spec §5) as the verifier sees it. This is a deliberately
// small, self-contained copy of the TrustNet audit taxonomy: it must match
// the producer's `internal/audit/events.go` for the same spec version, but the
// verifier does not import the service codebase.
package auditspec

// Event type names (spec §5).
const (
	TypeConsentGranted    = "consent.granted"
	TypeConsentDenied     = "consent.denied"
	TypeConsentRevoked    = "consent.revoked"
	TypeRPRegistered      = "rp.registered"
	TypeRPSettingsChanged = "rp.settings_changed"
	TypeRPSuspended       = "rp.suspended"
	TypeRPReinstated      = "rp.reinstated"
	TypeRPDeleted         = "rp.deleted"
	TypeRPReported        = "rp.reported"
	TypeRPPurged          = "rp.purged"
	TypePurposeRegistered = "purpose.registered"
	TypePurposeUpdated    = "purpose.updated"
	TypeAuditKeyCreated   = "audit_key.created"
	TypeAuditKeyRotated   = "audit_key.rotated"
	TypeAuditKeyRevoked   = "audit_key.revoked"
	TypeTSAChanged        = "tsa.changed"

	TypeRevocationEffected  = "revocation.effected"
	TypeErasureRequested    = "erasure.requested"
	TypeErasureExecuted     = "erasure.executed"
	TypeExportGenerated     = "export.generated"
	TypeDisclosureReadBatch = "disclosure.read_batch"

	TypeAuthLogin                   = "auth.login"
	TypeAuthLogout                  = "auth.logout"
	TypeAuthLoginIPObserved         = "auth.login.ip_observed"
	TypeCredentialPasswordReset     = "credential.password_reset"
	TypeCredentialPasskeyRegistered = "credential.passkey_registered"
	TypeCredentialPasskeyRemoved    = "credential.passkey_removed"
	TypeAccountRecovered            = "account.recovered"
	TypeAccountLinkedExternalIDP    = "account.linked_external_idp"
	TypeAccountUnlinkedExternalIDP  = "account.unlinked_external_idp"
	TypeMFAEnrolled                 = "mfa.enrolled"
	TypeMFARemoved                  = "mfa.removed"
	TypeContactAdded                = "contact.added"
	TypeContactVerified             = "contact.verified"
	TypeContactRemoved              = "contact.removed"
)

// StorableTypes is the set of event types the producer may write (spec §5).
// The verifier warns on a type outside this set; it does not fail the bundle,
// so a newer producer taxonomy stays verifiable by an older verifier.
var StorableTypes = map[string]struct{}{
	TypeConsentGranted:              {},
	TypeConsentDenied:               {},
	TypeConsentRevoked:              {},
	TypeRPRegistered:                {},
	TypeRPSettingsChanged:           {},
	TypeRPSuspended:                 {},
	TypeRPReinstated:                {},
	TypeRPDeleted:                   {},
	TypeRPReported:                  {},
	TypeRPPurged:                    {},
	TypePurposeRegistered:           {},
	TypePurposeUpdated:              {},
	TypeAuditKeyCreated:             {},
	TypeAuditKeyRotated:             {},
	TypeAuditKeyRevoked:             {},
	TypeTSAChanged:                  {},
	TypeRevocationEffected:          {},
	TypeErasureRequested:            {},
	TypeErasureExecuted:             {},
	TypeExportGenerated:             {},
	TypeDisclosureReadBatch:         {},
	TypeAuthLogin:                   {},
	TypeAuthLogout:                  {},
	TypeAuthLoginIPObserved:         {},
	TypeCredentialPasswordReset:     {},
	TypeCredentialPasskeyRegistered: {},
	TypeCredentialPasskeyRemoved:    {},
	TypeAccountRecovered:            {},
	TypeAccountLinkedExternalIDP:    {},
	TypeAccountUnlinkedExternalIDP:  {},
	TypeMFAEnrolled:                 {},
	TypeMFARemoved:                  {},
	TypeContactAdded:                {},
	TypeContactVerified:             {},
	TypeContactRemoved:              {},
}

// PurposeRef identifies one immutable purpose version (spec §5 semantics 3).
type PurposeRef struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

// ExportRange is the seq range an export covers (spec §5 export.generated).
type ExportRange struct {
	FromSeq int64 `json:"from_seq"`
	ToSeq   int64 `json:"to_seq"`
}
