package auditspec

// TSAIdentity is the per-anchor TSA identity (spec §9): which authority bound
// this anchor. Self mode records just the mode; rfc3161 mode also records the
// endpoint and the chain hash of the token it returned.
type TSAIdentity struct {
	Mode          string `json:"mode"` // "self" | "rfc3161"
	URL           string `json:"url,omitempty"`
	CertChainHash string `json:"cert_chain_hash,omitempty"`
}
