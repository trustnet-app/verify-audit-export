package verify

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"time"
)

// File is one entry of a bundle archive.
type File struct {
	Name string
	Data []byte
}

// WriteArchive serializes files into a deterministic tar.gz: entries sorted
// by name, zeroed timestamps, fixed gzip header — the same input always
// produces the same bytes, so the manifest's file digests are reproducible
// and two identical bundles byte-compare equal.
func WriteArchive(files []File) ([]byte, error) {
	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.ModTime = time.Time{}
	gz.OS = 255 // unknown OS: deterministic across platforms
	tw := tar.NewWriter(gz)
	for _, f := range sorted {
		if err := tw.WriteHeader(&tar.Header{
			Name:    f.Name,
			Mode:    0o644,
			Size:    int64(len(f.Data)),
			ModTime: time.Time{},
		}); err != nil {
			return nil, fmt.Errorf("export: archive: write header %s: %w", f.Name, err)
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, fmt.Errorf("export: archive: write %s: %w", f.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("export: archive: close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("export: archive: close gzip: %w", err)
	}
	return buf.Bytes(), nil
}

// ReadArchive reads a tar.gz and returns its regular-file entries keyed by
// name. The verifier uses it to lay the bundle open without touching disk.
func ReadArchive(data []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("export: archive: gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("export: archive: read: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("export: archive: read %s: %w", hdr.Name, err)
		}
		out[hdr.Name] = b
	}
	return out, nil
}

// Digest returns the hex SHA-256 of data.
func Digest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
