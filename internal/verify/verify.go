// Package verify provides binary checksum validation and integrity
// verification.
//
// Per §4.3: Checksum validation (SHA-256, SHA-512), signature verification,
// and comparison against known-good baselines.
package verify

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"time"

	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// Algorithm represents a supported hash algorithm.
type Algorithm string

const (
	SHA256 Algorithm = "sha256"
	SHA512 Algorithm = "sha512"
)

// Result holds the outcome of a checksum verification.
type Result struct {
	Path      string    `json:"path"`
	Algorithm Algorithm `json:"algorithm"`
	Expected  string    `json:"expected"`
	Actual    string    `json:"actual"`
	Match     bool      `json:"match"`
}

// Verifier provides checksum computation and validation.
type Verifier struct{}

// New creates a new Verifier.
func New() *Verifier {
	return &Verifier{}
}

// ComputeChecksum computes the hash of a file using the specified algorithm.
func (v *Verifier) ComputeChecksum(ctx context.Context, path string, algo Algorithm) (string, error) {
	ctx = logger.WithComponent(ctx, "verify")

	logger.Info(ctx, "computing checksum",
		"path", path,
		"algorithm", string(algo),
	)

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("verify: open %s: %w", path, err)
	}
	defer f.Close()

	h, err := newHash(algo)
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("verify: hash %s: %w", path, err)
	}

	checksum := hex.EncodeToString(h.Sum(nil))

	logger.Info(ctx, "checksum computed",
		"path", path,
		"algorithm", string(algo),
		"checksum", checksum,
		"outcome", "success",
	)

	return checksum, nil
}

// VerifyChecksum computes the hash of a file and compares it against the
// expected value.
func (v *Verifier) VerifyChecksum(ctx context.Context, path string, algo Algorithm, expected string) (Result, error) {
	ctx = logger.WithComponent(ctx, "verify")

	actual, err := v.ComputeChecksum(ctx, path, algo)
	if err != nil {
		return Result{}, err
	}

	result := Result{
		Path:      path,
		Algorithm: algo,
		Expected:  expected,
		Actual:    actual,
		Match:     actual == expected,
	}

	if result.Match {
		logger.Info(ctx, "checksum verification passed",
			"path", path,
			"algorithm", string(algo),
			"outcome", "match",
		)
	} else {
		logger.Warn(ctx, "checksum verification FAILED",
			"path", path,
			"algorithm", string(algo),
			"expected", expected,
			"actual", actual,
			"outcome", "mismatch",
		)
	}

	return result, nil
}

// VerifyBaseline checks a set of files against their expected checksums.
// The baseline is a map of file paths to expected SHA-256 hex strings.
func (v *Verifier) VerifyBaseline(ctx context.Context, baseline map[string]string) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "verify")

	logger.Info(ctx, "verifying file baseline",
		"file_count", len(baseline),
	)

	var findings []protocol.Finding

	for path, expected := range baseline {
		result, err := v.VerifyChecksum(ctx, path, SHA256, expected)
		if err != nil {
			// File missing or unreadable is itself a finding.
			findings = append(findings, protocol.NewFinding(protocol.FindingSpec{
				Severity:    protocol.SeverityHigh,
				Category:    "integrity-check",
				Description: fmt.Sprintf("Cannot verify integrity of %s: %v", path, err),
				Evidence: map[string]any{
					"path":  path,
					"error": err.Error(),
				},
				Impact:         "A file that cannot be verified may have been tampered with or removed.",
				Recommendation: fmt.Sprintf("Investigate why %s cannot be read. Restore from a known-good backup if necessary.", path),
				Timestamp:      time.Now().UTC(),
			}))
			continue
		}

		if !result.Match {
			findings = append(findings, protocol.NewFinding(protocol.FindingSpec{
				Severity:    protocol.SeverityCritical,
				Category:    "integrity-violation",
				Description: fmt.Sprintf("File %s has been modified — checksum mismatch", path),
				Evidence: map[string]any{
					"path":            path,
					"expected_sha256": result.Expected,
					"actual_sha256":   result.Actual,
				},
				Impact:         "A modified binary or configuration file may indicate tampering, supply-chain compromise, or unauthorized changes.",
				Recommendation: fmt.Sprintf("Quarantine %s immediately. Compare against known-good copy. Investigate how the modification occurred.", path),
				Timestamp:      time.Now().UTC(),
			}))
		}
	}

	logger.Info(ctx, "baseline verification complete",
		"files_checked", len(baseline),
		"findings", len(findings),
		"outcome", "success",
	)

	return findings, nil
}

// SelfCheck verifies the integrity of the running Mitiga binary.
func (v *Verifier) SelfCheck(ctx context.Context, expectedHash string) error {
	ctx = logger.WithComponent(ctx, "verify")

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("verify: resolve executable path: %w", err)
	}

	logger.Info(ctx, "performing self-integrity check",
		"binary", execPath,
	)

	result, err := v.VerifyChecksum(ctx, execPath, SHA256, expectedHash)
	if err != nil {
		return fmt.Errorf("verify: self-check: %w", err)
	}

	if !result.Match {
		logger.Critical(ctx, "SELF-INTEGRITY CHECK FAILED — binary may be tampered",
			"binary", execPath,
			"expected", expectedHash,
			"actual", result.Actual,
		)
		return fmt.Errorf("verify: self-check: %w: expected %s got %s",
			protocol.ErrHashMismatch, expectedHash, result.Actual)
	}

	logger.Info(ctx, "self-integrity check passed",
		"binary", execPath,
		"outcome", "success",
	)

	return nil
}

// newHash returns the appropriate hash.Hash for the algorithm.
func newHash(algo Algorithm) (hash.Hash, error) {
	switch algo {
	case SHA256:
		return sha256.New(), nil
	case SHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("verify: unsupported algorithm: %s", algo)
	}
}
