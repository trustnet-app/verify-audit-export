package auditspec

// ProducerInfo identifies the software that wrote the event (spec §4/§22).
type ProducerInfo struct {
	Service string `json:"service"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}
