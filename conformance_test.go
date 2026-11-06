package verify

// conformance_test.go — the offline verifier's conformance corpus
// (spec §10.1). Every link of the v1 bundle's trust chain is exercised
// against a fully synthetic bundle built in-memory: an ed25519 keypair,
// canonical envelopes, an STH signed with the raw key, and a self-mode anchor
// (meta_root = HashLeaf(sth canonical bytes), empty inclusion proof, index 0,
// tree_count 1). No DB, no Vault — the verifier must pass the valid fixture
// and catch each targeted mutation.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	audit "github.com/trustnet-app/verify-audit-export/internal/auditspec"
)

// memSigner is the in-memory Ed25519 audit signer.
type memSigner struct {
	kid  string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newMemSigner(kid string) *memSigner {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &memSigner{kid: kid, pub: pub, priv: priv}
}

func pemPublicKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// signJWS builds a compact EdDSA JWS with the fixture signer.
func signJWS(t *testing.T, s *memSigner, payload []byte) string {
	t.Helper()
	hdr := mustJSON(jwsHeader{Alg: "EdDSA", Kid: s.kid})
	signingInput := b64url(hdr) + "." + b64url(payload)
	sig := ed25519.Sign(s.priv, []byte(signingInput))
	return signingInput + "." + b64url(sig)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// conformance fixture constants: one purpose version and one consent
// wording, referenced by the synthetic purpose/consent events below.
const (
	conformanceTree         = "rp:conformance"
	conformancePurposeID    = "marketing"
	conformancePurposeBody  = "We use your data for marketing purposes."
	conformanceConsentBody  = "Do you consent to marketing?"
	conformanceProducer     = `{"service":"persona-api","version":"test","commit":"m2.4.6"}`
	conformanceRPRegistered = `{"client_name":"Local demo RP","redirect_uri_hashes":[],"initial_settings":{"subject_type":"pairwise","access_token_strategy":"jwt","skip_consent":false}}`
)

// conformanceEvents is the valid corpus: rp.registered (leaf 0),
// purpose.registered anchoring the purpose text, then a consent.granted
// referencing both. buildBundle fills in v/tree/seq/ts/actor/producer.
func conformanceEvents() []audit.Envelope {
	return []audit.Envelope{
		{Type: audit.TypeRPRegistered, Payload: json.RawMessage(conformanceRPRegistered)},
		{Type: audit.TypePurposeRegistered, Payload: mustJSON(map[string]any{
			"purpose_ref": audit.PurposeRef{ID: conformancePurposeID, Version: 1},
			"text_hash":   Digest([]byte(conformancePurposeBody)),
		})},
		{Type: audit.TypeConsentGranted, Payload: mustJSON(map[string]any{
			"purpose_ref":          audit.PurposeRef{ID: conformancePurposeID, Version: 1},
			"consent_text_version": 1,
		})},
	}
}

// buildBundle assembles a complete, valid v1 bundle for the given events
// and returns the archive's file map plus the signer (so mutation tests can
// re-sign a changed manifest). The events need only their Type and Payload
// (and any deliberate deviation, e.g. V or Type overrides); the envelope
// scaffolding, STH, anchor, keys and manifest are derived deterministically.
func buildBundle(t *testing.T, events []audit.Envelope) (map[string][]byte, *memSigner) {
	t.Helper()
	s := newMemSigner("conformance-audit:v1")
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	var buf bytes.Buffer
	leaves := make([][]byte, 0, len(events))
	for i, env := range events {
		if env.V == 0 {
			env.V = 2
		}
		env.Tree = conformanceTree
		env.Seq = int64(i)
		if env.EventID == "" {
			env.EventID = fmt.Sprintf("ev-%d", i)
		}
		if env.TS.IsZero() {
			env.TS = base.Add(time.Duration(i) * time.Second)
		}
		if len(env.Actor) == 0 {
			env.Actor = json.RawMessage(`{"kind":"rp"}`)
		}
		if len(env.Producer) == 0 {
			env.Producer = json.RawMessage(conformanceProducer)
		}
		canon, err := env.CanonicalBytes()
		if err != nil {
			t.Fatalf("canonical envelope %d: %v", i, err)
		}
		buf.Write(canon)
		buf.WriteByte('\n')
		leaves = append(leaves, audit.HashLeaf(canon))
	}
	eventsFile := buf.Bytes()

	sth := audit.STH{
		V:        1,
		Tree:     conformanceTree,
		TreeSize: uint64(len(events)),
		RootHash: mth(leaves, 0, len(leaves)),
		STHTime:  base.Add(time.Duration(len(events)+1) * time.Second),
		KeyID:    s.kid,
		Producer: audit.ProducerInfo{Service: "persona-api", Version: "test", Commit: "m2.4.6"},
		Clock:    audit.Clock{Source: "system", OffsetMS: 0, SyncStatus: "unsynchronized"},
	}
	sthCanon, err := sth.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical sth: %v", err)
	}
	sthSig := ed25519.Sign(s.priv, sthCanon)
	sthFile := mustJSON(sthFilePayload{STH: sthCanon, Signature: sthSig})
	rangeFile := mustJSON(rangeFilePayload{
		FromSeq:   0,
		ToSeq:     int64(len(events) - 1),
		LeafCount: int64(len(events)),
		RootHash:  sth.RootHash,
	})

	// Self-mode anchor over the single tree: meta_root = the STH leaf,
	// empty inclusion proof, index 0, tree_count 1.
	metaRoot := audit.HashLeaf(sthCanon)
	selfKeyID := s.kid
	anchor := anchorFilePayload{
		AnchorTime:    base.Add(24 * time.Hour),
		MetaRoot:      metaRoot,
		SelfSignature: ed25519.Sign(s.priv, metaRoot),
		SelfKeyID:     &selfKeyID,
		TSAIdentity:   mustJSON(audit.TSAIdentity{Mode: "self"}),
		Clock:         mustJSON(audit.Clock{Source: "system", OffsetMS: 0, SyncStatus: "unsynchronized"}),
		ThisTree: anchorTreeFile{
			Tree:           conformanceTree,
			STH:            sthCanon,
			STHSignature:   sthSig,
			InclusionProof: [][]byte{},
			Index:          0,
			TreeCount:      1,
		},
	}
	anchorName := "anchors/" + anchor.AnchorTime.UTC().Format("2006-01-02") + ".json"
	anchorFile := mustJSON(anchor)

	purposesFile := mustJSON(struct {
		PurposeID string `json:"purpose_id"`
		ClientID  string `json:"client_id"`
		Version   int    `json:"version"`
		Name      string `json:"name"`
		Body      string `json:"body"`
		TextHash  string `json:"text_hash"`
	}{
		PurposeID: conformancePurposeID,
		ClientID:  strings.TrimPrefix(conformanceTree, "rp:"),
		Version:   1,
		Name:      "Marketing",
		Body:      conformancePurposeBody,
		TextHash:  Digest([]byte(conformancePurposeBody)),
	})
	consentTextsFile := mustJSON(struct {
		Version  int    `json:"version"`
		Body     string `json:"body"`
		TextHash string `json:"text_hash"`
	}{
		Version:  1,
		Body:     conformanceConsentBody,
		TextHash: Digest([]byte(conformanceConsentBody)),
	})

	keys := []audit.KeyRecord{{
		KeyID:     s.kid,
		PublicKey: pemPublicKey(t, s.pub),
		Algorithm: "Ed25519",
		Status:    audit.KeyStatusActive,
		CreatedAt: base,
	}}
	keysFile := mustJSON(keys)

	files := map[string][]byte{
		"events.jsonl":        eventsFile,
		"purposes.jsonl":      purposesFile,
		"consent_texts.jsonl": consentTextsFile,
		"proofs/sth.json":     sthFile,
		"proofs/range.json":   rangeFile,
		"keys.json":           keysFile,
		"VERIFY.md":           []byte("# TrustNet audit export — verification\n"),
		anchorName:            anchorFile,
	}

	payload := ManifestPayload{
		BundleVersion: BundleVersionRP,
		Tree:          conformanceTree,
		Range:         audit.ExportRange{FromSeq: 0, ToSeq: int64(len(events) - 1)},
		EventCount:    int64(len(events)),
		Files:         map[string]string{},
		KeyID:         s.kid,
		GeneratedAt:   base.Add(2 * time.Hour),
	}
	resignManifest(t, s, files, payload)
	return files, s
}

// resignManifest recomputes the file digests (except manifest.json itself)
// and signs the manifest with the fixture signer — used at build time and by
// mutations that change file contents while keeping a valid JWS.
func resignManifest(t *testing.T, s *memSigner, files map[string][]byte, payload ManifestPayload) {
	t.Helper()
	payload.Files = map[string]string{}
	for name, data := range files {
		if name == "manifest.json" {
			continue
		}
		payload.Files[name] = Digest(data)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal manifest payload: %v", err)
	}
	files["manifest.json"] = []byte(signJWS(t, s, b))
}

// manifestOf reads back the signed manifest payload from the file map.
func manifestOf(t *testing.T, files map[string][]byte) ManifestPayload {
	t.Helper()
	var keys []audit.KeyRecord
	if err := json.Unmarshal(files["keys.json"], &keys); err != nil {
		t.Fatalf("unmarshal keys.json: %v", err)
	}
	raw, _, err := verifyJWS(string(files["manifest.json"]), keys)
	if err != nil {
		t.Fatalf("verify manifest: %v", err)
	}
	var m ManifestPayload
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal manifest payload: %v", err)
	}
	return m
}

func archiveFromFiles(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	list := make([]File, 0, len(files))
	for name, data := range files {
		list = append(list, File{Name: name, Data: data})
	}
	archive, err := WriteArchive(list)
	if err != nil {
		t.Fatalf("write archive: %v", err)
	}
	return archive
}

func mustContain(t *testing.T, findings []string, substr string) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f, substr) {
			return
		}
	}
	t.Fatalf("findings %q do not contain %q", findings, substr)
}

// TestVerifyConformanceValid: the honest fixture verifies — no errors, the
// self-anchored tier raises the expected degraded-trust warning, and the
// informational manifest line is present.
func TestVerifyConformanceValid(t *testing.T) {
	files, _ := buildBundle(t, conformanceEvents())
	verdict, err := VerifyBundle(archiveFromFiles(t, files), VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !verdict.Valid() {
		t.Fatalf("valid bundle rejected: %v", verdict.Error())
	}
	mustContain(t, verdict.Warnings, "degraded trust: self-anchored")
	mustContain(t, verdict.Info, "manifest: kid")
	if len(verdict.Errors) != 0 {
		t.Fatalf("errors = %v", verdict.Errors)
	}
}

// TestVerifyConformanceMutations targets every link of the trust chain with
// one mutation each; the verifier must produce the intended finding.
func TestVerifyConformanceMutations(t *testing.T) {
	t.Run("broken jws", func(t *testing.T) {
		files, _ := buildBundle(t, conformanceEvents())
		parts := strings.Split(string(files["manifest.json"]), ".")
		if len(parts) != 3 {
			t.Fatalf("manifest is not compact JWS: %q", files["manifest.json"])
		}
		parts[2] = b64url([]byte("not the signature"))
		files["manifest.json"] = []byte(strings.Join(parts, "."))
		verdict, err := VerifyBundle(archiveFromFiles(t, files), VerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyBundle: %v", err)
		}
		mustContain(t, verdict.Errors, "manifest JWS")
	})

	t.Run("tampered event", func(t *testing.T) {
		files, s := buildBundle(t, conformanceEvents())
		files["events.jsonl"] = bytes.Replace(files["events.jsonl"],
			[]byte("Local demo RP"), []byte("Local demo RP "), 1) // payload text mutated
		resignManifest(t, s, files, manifestOf(t, files))
		verdict, err := VerifyBundle(archiveFromFiles(t, files), VerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyBundle: %v", err)
		}
		mustContain(t, verdict.Errors, "recomputed range root")
	})

	t.Run("swapped purpose text", func(t *testing.T) {
		files, s := buildBundle(t, conformanceEvents())
		// Change the body but keep the claimed text_hash: the digest check
		// must fire even though the manifest still binds the file.
		files["purposes.jsonl"] = bytes.Replace(files["purposes.jsonl"],
			[]byte(conformancePurposeBody), []byte(conformancePurposeBody+"."), 1)
		resignManifest(t, s, files, manifestOf(t, files))
		verdict, err := VerifyBundle(archiveFromFiles(t, files), VerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyBundle: %v", err)
		}
		mustContain(t, verdict.Errors, "SHA-256(purpose body)")
	})

	t.Run("consent after suspension", func(t *testing.T) {
		evs := []audit.Envelope{
			{Type: audit.TypeRPRegistered, Payload: json.RawMessage(conformanceRPRegistered)},
			{Type: audit.TypeRPSuspended, Payload: mustJSON(map[string]any{
				"reason_category": "operational",
				"effects": map[string]any{
					"login_blocked":   true,
					"consent_blocked": true,
				},
			})},
			{Type: audit.TypeConsentGranted, Payload: mustJSON(map[string]any{
				"purpose_ref":          audit.PurposeRef{ID: conformancePurposeID, Version: 1},
				"consent_text_version": 1,
			})},
		}
		files, _ := buildBundle(t, evs)
		verdict, err := VerifyBundle(archiveFromFiles(t, files), VerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyBundle: %v", err)
		}
		mustContain(t, verdict.Errors, "suspension invariant")
	})

	t.Run("missing anchor", func(t *testing.T) {
		files, _ := buildBundle(t, conformanceEvents())
		// Delete the anchor file but leave the manifest listing it: the
		// digest loop must report the archive lacking a listed file.
		anchorName := "anchors/2026-08-23.json"
		if _, ok := files[anchorName]; !ok {
			t.Fatalf("fixture anchor name %s not present (have %v)", anchorName, keysOfFiles(files))
		}
		delete(files, anchorName)
		verdict, err := VerifyBundle(archiveFromFiles(t, files), VerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyBundle: %v", err)
		}
		mustContain(t, verdict.Errors, "manifest lists")
		mustContain(t, verdict.Errors, "but the archive lacks it")
	})

	t.Run("wrong event count", func(t *testing.T) {
		files, s := buildBundle(t, conformanceEvents())
		m := manifestOf(t, files)
		m.EventCount++
		resignManifest(t, s, files, m)
		verdict, err := VerifyBundle(archiveFromFiles(t, files), VerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyBundle: %v", err)
		}
		mustContain(t, verdict.Errors, "manifest event_count")
	})

	t.Run("unknown envelope v", func(t *testing.T) {
		evs := conformanceEvents()
		evs[2].V = 3
		files, _ := buildBundle(t, evs)
		verdict, err := VerifyBundle(archiveFromFiles(t, files), VerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyBundle: %v", err)
		}
		mustContain(t, verdict.Errors, "unknown envelope v 3")
	})

	t.Run("unknown event type warns only", func(t *testing.T) {
		evs := conformanceEvents()
		evs[2].Type = "mystery.event"
		files, _ := buildBundle(t, evs)
		verdict, err := VerifyBundle(archiveFromFiles(t, files), VerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyBundle: %v", err)
		}
		if !verdict.Valid() {
			t.Fatalf("unknown event type must not fail the bundle: %v", verdict.Error())
		}
		mustContain(t, verdict.Warnings, "unknown event type \"mystery.event\"")
	})
}

func keysOfFiles(files map[string][]byte) []string {
	out := make([]string, 0, len(files))
	for name := range files {
		out = append(out, name)
	}
	return out
}
