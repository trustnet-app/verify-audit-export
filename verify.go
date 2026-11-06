package verify

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	audit "github.com/trustnet-app/verify-audit-export/internal/auditspec"
)

// VerifyOptions configures a verification run.
type VerifyOptions struct {
	// Verbose records informational findings in Info; otherwise only
	// errors and warnings are kept.
	Verbose bool
}

// Verification collects the verifier's findings. Valid reports whether the
// bundle passed every hard check; Warnings are trust-degrading but not
// fatal (unknown event type, degraded TSA trust).
type Verification struct {
	Errors   []string
	Warnings []string
	Info     []string
}

// Valid reports whether the bundle passed every hard check.
func (v *Verification) Valid() bool { return len(v.Errors) == 0 }

// Error summarizes the failures (the CLI prints it with exit code 1).
func (v *Verification) Error() string {
	return strings.Join(v.Errors, "\n")
}

func (v *Verification) errorf(format string, args ...any) {
	v.Errors = append(v.Errors, fmt.Sprintf(format, args...))
}

func (v *Verification) warnf(format string, args ...any) {
	v.Warnings = append(v.Warnings, fmt.Sprintf(format, args...))
}

func (v *Verification) infof(format string, args ...any) {
	v.Info = append(v.Info, fmt.Sprintf(format, args...))
}

// envelopeShape is the envelope fields the verifier checks before hashing.
// The same JSON names as audit.Envelope.
type envelopeShape struct {
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

// VerifyBundle verifies an export bundle offline: a per-RP v1 bundle
// (spec §10.1) or an auth-period bundle (auth-events.md §9) — JWS and file
// digests, envelope shape, leaf hashes, the recomputed RFC 6962 range root
// against the signed tree head, the STH signature, the anchor's inclusion in
// the meta-tree plus its TSA token or self signature, and the consistency
// bridge (when present). The RP bundle additionally checks purpose/consent-text
// resolution and the five verifier obligations.
func VerifyBundle(archive []byte, opts VerifyOptions) (*Verification, error) {
	v := &Verification{}
	files, err := ReadArchive(archive)
	if err != nil {
		return nil, err
	}

	required := []string{
		"manifest.json", "events.jsonl",
		"proofs/sth.json", "proofs/range.json", "keys.json", "VERIFY.md",
	}
	for _, name := range required {
		if _, ok := files[name]; !ok {
			v.errorf("missing required file %s", name)
		}
	}
	if !v.Valid() {
		return v, nil
	}

	// The RP v1 bundle additionally requires the reference files; an
	// auth-period bundle (BundleVersionAuth) deliberately has none
	// (auth-events.md §9). The presence check therefore runs after the
	// manifest tells us which kind this is.
	if _, ok := files["purposes.jsonl"]; ok {
		if _, ok := files["consent_texts.jsonl"]; !ok {
			v.errorf("purposes.jsonl present but consent_texts.jsonl missing")
		}
	}
	if _, ok := files["consent_texts.jsonl"]; ok {
		if _, ok := files["purposes.jsonl"]; !ok {
			v.errorf("consent_texts.jsonl present but purposes.jsonl missing")
		}
	}

	// 1. JWS manifest + file digests.
	var keys []audit.KeyRecord
	if err := json.Unmarshal(files["keys.json"], &keys); err != nil {
		v.errorf("keys.json: %v", err)
		return v, nil
	}
	manifestPayload, kid, err := verifyJWS(string(files["manifest.json"]), keys)
	if err != nil {
		v.errorf("manifest JWS: %v", err)
		return v, nil
	}
	var manifest ManifestPayload
	if err := json.Unmarshal(manifestPayload, &manifest); err != nil {
		v.errorf("manifest payload: %v", err)
		return v, nil
	}
	v.infof("manifest: kid %s, tree %s, range [%d,%d], events %d", kid, manifest.Tree, manifest.Range.FromSeq, manifest.Range.ToSeq, manifest.EventCount)
	isRP := manifest.BundleVersion == BundleVersionRP
	isAuth := manifest.BundleVersion == BundleVersionAuth
	if !isRP && !isAuth {
		v.errorf("manifest bundle_version %q, want %q or %q", manifest.BundleVersion, BundleVersionRP, BundleVersionAuth)
	}
	if isRP {
		for _, name := range []string{"purposes.jsonl", "consent_texts.jsonl"} {
			if _, ok := files[name]; !ok {
				v.errorf("missing required file %s", name)
			}
		}
	}
	if manifest.KeyID != kid {
		v.errorf("manifest key_id %q differs from JWS kid %q", manifest.KeyID, kid)
	}
	for name, hash := range manifest.Files {
		data, ok := files[name]
		if !ok {
			v.errorf("manifest lists %s but the archive lacks it", name)
			continue
		}
		if Digest(data) != hash {
			v.errorf("manifest digest mismatch for %s", name)
		}
	}
	for name := range files {
		if name == "manifest.json" {
			continue
		}
		if _, listed := manifest.Files[name]; !listed {
			v.warnf("file %s is not listed in the manifest", name)
		}
	}

	// 2-3. Envelope shape per line + leaf hashes.
	lines := strings.Split(strings.TrimSuffix(string(files["events.jsonl"]), "\n"), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		v.errorf("events.jsonl is empty")
		return v, nil
	}
	events := make([]envelopeShape, 0, len(lines))
	leaves := make([][]byte, 0, len(lines))
	eventByID := make(map[string]int, len(lines))
	for i, line := range lines {
		var ev envelopeShape
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			v.errorf("events.jsonl line %d: not a JSON envelope: %v", i+1, err)
			continue
		}
		if ev.V != 2 {
			v.errorf("events.jsonl line %d (seq %d): unknown envelope v %d", i+1, ev.Seq, ev.V)
		}
		if len(ev.Producer) == 0 || !json.Valid(ev.Producer) {
			v.errorf("events.jsonl line %d (seq %d): missing or malformed producer", i+1, ev.Seq)
		}
		if _, known := audit.StorableTypes[ev.Type]; !known {
			v.warnf("events.jsonl line %d (seq %d): unknown event type %q", i+1, ev.Seq, ev.Type)
		}
		events = append(events, ev)
		leaves = append(leaves, audit.HashLeaf([]byte(line)))
		eventByID[ev.EventID] = i
	}
	if len(events) != len(lines) {
		v.errorf("events.jsonl: %d of %d lines parsed as envelopes", len(events), len(lines))
		return v, nil
	}
	if int64(len(lines)) != manifest.EventCount {
		v.errorf("manifest event_count %d, events.jsonl has %d", manifest.EventCount, len(lines))
	}

	// 4. Range root recomputation == STH root (the degenerate full-range proof).
	var sthFile struct {
		STH       json.RawMessage `json:"sth"`
		Signature []byte          `json:"signature"`
	}
	if err := json.Unmarshal(files["proofs/sth.json"], &sthFile); err != nil {
		v.errorf("proofs/sth.json: %v", err)
		return v, nil
	}
	var sth audit.STH
	if err := json.Unmarshal(sthFile.STH, &sth); err != nil {
		v.errorf("proofs/sth.json: sth: %v", err)
		return v, nil
	}
	canon, err := sth.CanonicalBytes()
	if err != nil {
		v.errorf("proofs/sth.json: sth canonical bytes: %v", err)
		return v, nil
	}
	if !bytes.Equal(canon, sthFile.STH) {
		v.errorf("proofs/sth.json: sth is not its own canonical bytes verbatim")
	}
	if sth.Tree != manifest.Tree {
		v.errorf("proofs/sth.json: sth tree %q, manifest tree %q", sth.Tree, manifest.Tree)
	}
	computedRoot := mth(leaves, 0, len(leaves))
	if !bytes.Equal(computedRoot, sth.RootHash) {
		v.errorf("recomputed range root %x != STH root %x", computedRoot, sth.RootHash)
	}
	var rangeFile rangeFilePayload
	if err := json.Unmarshal(files["proofs/range.json"], &rangeFile); err != nil {
		v.errorf("proofs/range.json: %v", err)
	} else {
		if rangeFile.FromSeq != 0 || rangeFile.ToSeq != int64(len(lines)-1) || rangeFile.LeafCount != int64(len(lines)) {
			v.errorf("proofs/range.json: range [%d,%d] count %d, want [0,%d] count %d", rangeFile.FromSeq, rangeFile.ToSeq, rangeFile.LeafCount, len(lines)-1, len(lines))
		}
		if !bytes.Equal(rangeFile.RootHash, sth.RootHash) {
			v.errorf("proofs/range.json root %x != STH root %x", rangeFile.RootHash, sth.RootHash)
		}
	}

	// 5. STH signature.
	if err := verifySTHWithKeys(v, sth, sthFile.Signature, keys); err != nil {
		v.errorf("proofs/sth.json signature: %v", err)
	}

	// 6. Anchor inclusion + TSA/self binding.
	verifyAnchors(v, files, keys, manifest.Tree)

	// 7. Consistency bridge.
	if data, ok := files["proofs/consistency.json"]; ok {
		var cf consistencyFilePayload
		if err := json.Unmarshal(data, &cf); err != nil {
			v.errorf("proofs/consistency.json: %v", err)
		} else {
			if cf.PrevSize >= cf.Size {
				v.errorf("proofs/consistency.json: prev_size %d >= size %d", cf.PrevSize, cf.Size)
			}
			if !bytes.Equal(cf.Root, sth.RootHash) {
				v.errorf("proofs/consistency.json: root %x != STH root %x", cf.Root, sth.RootHash)
			}
			if err := proof.VerifyConsistency(rfc6962.DefaultHasher, cf.PrevSize, cf.Size, cf.Proof, cf.PrevRoot, cf.Root); err != nil {
				v.errorf("proofs/consistency.json: %v", err)
			}
		}
	}

	// 8. Purpose/consent-text resolution — RP bundles only (an auth-period
	// bundle is account-scoped and carries no RP reference material).
	if isRP {
		resolveReferences(v, files, events)
	}

	// 9. The five verifier obligations — RP bundles only (they are the RP
	// lifecycle: leaf-0 registration, suspension, post-deletion export-only).
	if isRP {
		verifyObligations(v, events, eventByID)
	}

	if opts.Verbose {
		v.infof("verified %d events against STH %s size %d", len(events), sth.STHTime.Format(time.RFC3339), sth.TreeSize)
	}
	return v, nil
}

// verifySTHWithKeys verifies an STH signature against the key history.
func verifySTHWithKeys(v *Verification, sth audit.STH, sig []byte, keys []audit.KeyRecord) error {
	pub, err := resolvePublicKey(sth.KeyID, keys)
	if err != nil {
		return err
	}
	if err := audit.VerifySTH(sth, sig, pub); err != nil {
		return err
	}
	v.infof("sth %s size %d signature ok with key %s", sth.Tree, sth.TreeSize, sth.KeyID)
	return nil
}

// verifyAnchors checks every anchors/ file: this tree's STH inclusion in the
// meta-root, the anchored STH signature, and the meta-root's time binding
// (self signature or RFC 3161 token).
func verifyAnchors(v *Verification, files map[string][]byte, keys []audit.KeyRecord, tree string) {
	names := make([]string, 0, 1)
	for name := range files {
		if strings.HasPrefix(name, "anchors/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var af anchorFilePayload
		if err := json.Unmarshal(files[name], &af); err != nil {
			v.errorf("%s: %v", name, err)
			continue
		}
		if af.ThisTree.Tree != tree {
			v.errorf("%s: this_tree.tree %q, manifest tree %q", name, af.ThisTree.Tree, tree)
		}
		if af.ThisTree.Index < 0 || af.ThisTree.Index >= af.ThisTree.TreeCount {
			v.errorf("%s: this_tree.index %d out of range (tree_count %d)", name, af.ThisTree.Index, af.ThisTree.TreeCount)
		}
		var anchored audit.STH
		if err := json.Unmarshal(af.ThisTree.STH, &anchored); err != nil {
			v.errorf("%s: this_tree.sth: %v", name, err)
			continue
		}
		canon, err := anchored.CanonicalBytes()
		if err != nil {
			v.errorf("%s: this_tree.sth canonical bytes: %v", name, err)
			continue
		}
		if !bytes.Equal(canon, af.ThisTree.STH) {
			v.errorf("%s: this_tree.sth is not its own canonical bytes verbatim", name)
		}
		if anchored.Tree != tree {
			v.errorf("%s: anchored sth tree %q, manifest tree %q", name, anchored.Tree, tree)
		}
		if err := verifySTHWithKeys(v, anchored, af.ThisTree.STHSignature, keys); err != nil {
			v.errorf("%s: anchored sth signature: %v", name, err)
		}
		leaf := audit.HashLeaf(af.ThisTree.STH)
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(af.ThisTree.Index), uint64(af.ThisTree.TreeCount), leaf, af.ThisTree.InclusionProof, af.MetaRoot); err != nil {
			v.errorf("%s: anchored sth inclusion in meta-root: %v", name, err)
		}
		verifyAnchorBinding(v, name, af, keys)
	}
}

// verifyAnchorBinding checks how the meta-root is bound to time: self mode
// (Ed25519 signature by the audit key named in self_key_id) or rfc3161 mode
// (an RFC 3161 token verified offline against its embedded certificate
// chain).
func verifyAnchorBinding(v *Verification, name string, af anchorFilePayload, keys []audit.KeyRecord) {
	var ident audit.TSAIdentity
	if err := json.Unmarshal(af.TSAIdentity, &ident); err != nil {
		v.errorf("%s: tsa_identity: %v", name, err)
		return
	}
	switch ident.Mode {
	case "self":
		if len(af.SelfSignature) == 0 || af.SelfKeyID == nil {
			v.errorf("%s: self mode anchor lacks self_signature/self_key_id", name)
			return
		}
		pub, err := resolvePublicKey(*af.SelfKeyID, keys)
		if err != nil {
			v.errorf("%s: self mode key: %v", name, err)
			return
		}
		if !ed25519.Verify(pub, af.MetaRoot, af.SelfSignature) {
			v.errorf("%s: self signature over meta_root does not verify", name)
		}
		v.warnf("%s: degraded trust: self-anchored (dev/staging tier)", name)
	case "rfc3161":
		if len(af.TSAToken) == 0 {
			v.errorf("%s: rfc3161 anchor lacks tsa_token", name)
			return
		}
		ts, err := timestamp.Parse(af.TSAToken)
		if err != nil {
			v.errorf("%s: tsa token: %v", name, err)
			return
		}
		if !bytes.Equal(ts.HashedMessage, af.MetaRoot) {
			v.errorf("%s: tsa token imprints %x, anchor meta_root %x", name, ts.HashedMessage, af.MetaRoot)
		}
		if ts.HashAlgorithm != crypto.SHA256 {
			v.errorf("%s: tsa token hash %v, want SHA-256", name, ts.HashAlgorithm)
		}
		if len(ts.Certificates) > 0 {
			if got := certChainHashHex(ts.Certificates); ident.CertChainHash != "" && got != ident.CertChainHash {
				v.errorf("%s: tsa token chain hash %s, anchor claims %s", name, got, ident.CertChainHash)
			}
		} else {
			v.warnf("%s: degraded trust: tsa token embeds no certificates", name)
		}
	default:
		v.errorf("%s: unknown tsa_identity mode %q", name, ident.Mode)
	}
}

// resolveReferences checks purpose/consent-text resolution: every
// purpose_ref and consent_text_version referenced by events resolves in
// purposes.jsonl / consent_texts.jsonl, SHA-256(body) == text_hash == the
// matching purpose.registered/updated event's text_hash.
func resolveReferences(v *Verification, files map[string][]byte, events []envelopeShape) {
	purposesByVersion := map[int]purposeLine{}
	for _, line := range strings.Split(strings.TrimSuffix(string(files["purposes.jsonl"]), "\n"), "\n") {
		if line == "" {
			continue
		}
		var p purposeLine
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			v.errorf("purposes.jsonl line: %v", err)
			continue
		}
		purposesByVersion[p.Version] = p
	}
	consentByVersion := map[int]consentTextLine{}
	for _, line := range strings.Split(strings.TrimSuffix(string(files["consent_texts.jsonl"]), "\n"), "\n") {
		if line == "" {
			continue
		}
		var c consentTextLine
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			v.errorf("consent_texts.jsonl line: %v", err)
			continue
		}
		consentByVersion[c.Version] = c
	}
	// text_hash of every purpose event, keyed by version.
	purposeEventHashes := map[int]string{}
	for _, ev := range events {
		switch ev.Type {
		case audit.TypePurposeRegistered, audit.TypePurposeUpdated:
			var p struct {
				PurposeRef audit.PurposeRef `json:"purpose_ref"`
				TextHash   string           `json:"text_hash"`
			}
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				v.errorf("seq %d: %s payload: %v", ev.Seq, ev.Type, err)
				continue
			}
			purposeEventHashes[p.PurposeRef.Version] = p.TextHash
		}
	}
	for _, ev := range events {
		if ev.Type != audit.TypeConsentGranted && ev.Type != audit.TypeConsentDenied {
			continue
		}
		var p struct {
			PurposeRef         audit.PurposeRef `json:"purpose_ref"`
			ConsentTextVersion int              `json:"consent_text_version"`
		}
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			v.errorf("seq %d: %s payload: %v", ev.Seq, ev.Type, err)
			continue
		}
		pur, ok := purposesByVersion[p.PurposeRef.Version]
		if !ok {
			v.errorf("seq %d: purpose_ref version %d not found in purposes.jsonl", ev.Seq, p.PurposeRef.Version)
			continue
		}
		if pur.PurposeID != p.PurposeRef.ID {
			v.errorf("seq %d: purpose_ref id %q, purposes.jsonl has %q", ev.Seq, p.PurposeRef.ID, pur.PurposeID)
		}
		if got := Digest([]byte(pur.Body)); got != pur.TextHash {
			v.errorf("seq %d: SHA-256(purpose body) %s != text_hash %s", ev.Seq, got, pur.TextHash)
		}
		eventHash, ok := purposeEventHashes[p.PurposeRef.Version]
		if !ok {
			v.errorf("seq %d: purpose version %d has no purpose.registered/updated event", ev.Seq, p.PurposeRef.Version)
		} else if eventHash != pur.TextHash {
			v.errorf("seq %d: purpose event text_hash %s != purposes.jsonl text_hash %s", ev.Seq, eventHash, pur.TextHash)
		}
		ct, ok := consentByVersion[p.ConsentTextVersion]
		if !ok {
			v.errorf("seq %d: consent_text_version %d not found in consent_texts.jsonl", ev.Seq, p.ConsentTextVersion)
			continue
		}
		if got := Digest([]byte(ct.Body)); got != ct.TextHash {
			v.errorf("seq %d: SHA-256(consent text body) %s != text_hash %s", ev.Seq, got, ct.TextHash)
		}
	}
}

// verifyObligations runs the five verifier obligations (spec §10.1): (1)
// reference integrity — supersedes/revokes/suspension_ref point at earlier
// same-tree compatible events; (2) refs resolve + hashes match (checked in
// resolveReferences); (3) the suspension invariant; (4) leaf 0 is
// rp.registered, at most one rp.deleted, only export.generated after it;
// (5) envelope v/producer (checked in the envelope pass).
func verifyObligations(v *Verification, events []envelopeShape, eventByID map[string]int) {
	// (1) reference integrity.
	for i, ev := range events {
		switch ev.Type {
		case audit.TypeConsentGranted:
			var p struct {
				PurposeRef audit.PurposeRef  `json:"purpose_ref"`
				Supersedes *audit.PurposeRef `json:"supersedes"`
			}
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				v.errorf("seq %d: consent.granted payload: %v", ev.Seq, err)
				continue
			}
			if p.Supersedes != nil {
				if p.Supersedes.Version >= p.PurposeRef.Version {
					v.errorf("seq %d: supersedes version %d is not earlier than purpose version %d", ev.Seq, p.Supersedes.Version, p.PurposeRef.Version)
				}
				if !hasPurposeEventVersion(events, p.Supersedes.Version) {
					v.errorf("seq %d: superseded purpose version %d has no purpose event", ev.Seq, p.Supersedes.Version)
				}
			}
		case audit.TypeConsentRevoked:
			var p struct {
				Revokes string `json:"revokes"`
			}
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				v.errorf("seq %d: consent.revoked payload: %v", ev.Seq, err)
				continue
			}
			if idx, ok := eventByID[p.Revokes]; !ok || idx >= i {
				v.errorf("seq %d: consent.revoked revokes %q which is not an earlier event in this bundle", ev.Seq, p.Revokes)
			} else if events[idx].Type != audit.TypeConsentGranted {
				v.errorf("seq %d: consent.revoked revokes %q, but that event is %q", ev.Seq, p.Revokes, events[idx].Type)
			}
		case audit.TypeRPReinstated:
			var p struct {
				SuspensionRef string `json:"suspension_ref"`
			}
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				v.errorf("seq %d: rp.reinstated payload: %v", ev.Seq, err)
				continue
			}
			if idx, ok := eventByID[p.SuspensionRef]; !ok || idx >= i {
				v.errorf("seq %d: rp.reinstated suspension_ref %q is not an earlier event in this bundle", ev.Seq, p.SuspensionRef)
			} else if events[idx].Type != audit.TypeRPSuspended {
				v.errorf("seq %d: rp.reinstated suspension_ref %q, but that event is %q", ev.Seq, p.SuspensionRef, events[idx].Type)
			}
		}
	}

	// (3) suspension invariant over the full range.
	types := make([]string, len(events))
	for i, ev := range events {
		types[i] = ev.Type
	}
	if err := audit.CheckSuspensionInvariant(types); err != nil {
		v.errorf("suspension invariant: %v", err)
	}

	// (4) leaf 0 / deleted / post-deletion.
	if len(events) > 0 && events[0].Type != audit.TypeRPRegistered {
		v.errorf("leaf 0 is %q, want rp.registered", events[0].Type)
	}
	deletedCount := 0
	for _, ev := range events {
		if ev.Type == audit.TypeRPDeleted {
			deletedCount++
		}
	}
	if deletedCount > 1 {
		v.errorf("bundle contains %d rp.deleted events, at most one allowed", deletedCount)
	}
	for i, ev := range events {
		if ev.Type == audit.TypeRPDeleted {
			for j := i + 1; j < len(events); j++ {
				if events[j].Type != audit.TypeExportGenerated {
					v.errorf("seq %d: event %q after rp.deleted — only export.generated allowed", events[j].Seq, events[j].Type)
				}
			}
			break
		}
	}
}

// hasPurposeEventVersion reports whether any purpose.registered/updated event
// anchors the given version.
func hasPurposeEventVersion(events []envelopeShape, version int) bool {
	for _, ev := range events {
		if ev.Type != audit.TypePurposeRegistered && ev.Type != audit.TypePurposeUpdated {
			continue
		}
		var p struct {
			PurposeRef audit.PurposeRef `json:"purpose_ref"`
		}
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			continue
		}
		if p.PurposeRef.Version == version {
			return true
		}
	}
	return false
}

// purposeLine / consentTextLine mirror the JSONL line shapes the builder
// writes (bundle.go), used by the verifier's resolution pass.
type purposeLine struct {
	PurposeID string `json:"purpose_id"`
	ClientID  string `json:"client_id"`
	Version   int    `json:"version"`
	Name      string `json:"name"`
	Body      string `json:"body"`
	TextHash  string `json:"text_hash"`
}

type consentTextLine struct {
	Version  int    `json:"version"`
	Body     string `json:"body"`
	TextHash string `json:"text_hash"`
}

// certChainHashHex is hex SHA-256 over the concatenated DER bytes of the
// certificates in the order the token returned them — the same computation
// the anchor job used for tsa_identity.cert_chain_hash.
func certChainHashHex(certs []*x509.Certificate) string {
	h := sha256.New()
	for _, c := range certs {
		h.Write(c.Raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}
