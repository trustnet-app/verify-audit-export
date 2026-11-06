// Command trustnet-verify is the offline verifier CLI: it answers the
// canonical auditor question (spec §10.1) against a per-RP v1 or auth-period
// bundle without touching any service — the bundle is self-contained (manifest
// JWS, events, STH, anchor, keys).
//
//	trustnet-verify [-verbose] bundle.tar.gz
//
// Exit code 0 means every hard check passed; 1 means the bundle is invalid
// (or could not be read). Warnings are printed but do not fail the run:
// they flag trust-degrading conditions (unknown event type, self-anchored
// tier, TSA token without certificates).
package main

import (
	"flag"
	"fmt"
	"os"

	verify "github.com/trustnet-app/verify-audit-export"
)

func main() {
	verbose := flag.Bool("verbose", false, "print informational findings")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: trustnet-verify [-verbose] bundle.tar.gz")
		os.Exit(2)
	}
	path := flag.Arg(0)

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustnet-verify: read %s: %v\n", path, err)
		os.Exit(1)
	}

	verdict, err := verify.VerifyBundle(data, verify.VerifyOptions{Verbose: *verbose})
	if err != nil {
		fmt.Fprintf(os.Stderr, "trustnet-verify: %v\n", err)
		os.Exit(1)
	}

	printFindings("info", verdict.Info)
	printFindings("warning", verdict.Warnings)
	printFindings("error", verdict.Errors)

	if verdict.Valid() {
		fmt.Printf("trustnet-verify: %s: VALID — the audit trail is intact and provable (spec §10.1)\n", path)
		os.Exit(0)
	}
	fmt.Printf("trustnet-verify: %s: INVALID — %d error(s) found\n", path, len(verdict.Errors))
	os.Exit(1)
}

func printFindings(kind string, findings []string) {
	for _, f := range findings {
		fmt.Printf("  %-7s %s\n", kind, f)
	}
}
