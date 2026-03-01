package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

func TestComputeChecksum_SHA256(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "verify-test-*")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("hello mitiga\n")
	tmpFile.Write(content)
	tmpFile.Close()

	h := sha256.New()
	h.Write(content)
	expected := hex.EncodeToString(h.Sum(nil))

	v := New()
	actual, err := v.ComputeChecksum(context.Background(), tmpFile.Name(), SHA256)
	if err != nil {
		t.Fatalf("ComputeChecksum: %v", err)
	}

	if actual != expected {
		t.Errorf("checksum mismatch: got %q, want %q", actual, expected)
	}
}

func TestComputeChecksum_SHA512(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "verify-test-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Write([]byte("test data"))
	tmpFile.Close()

	v := New()
	checksum, err := v.ComputeChecksum(context.Background(), tmpFile.Name(), SHA512)
	if err != nil {
		t.Fatalf("ComputeChecksum SHA512: %v", err)
	}

	if len(checksum) != 128 {
		t.Errorf("SHA-512 hash length: got %d, want 128", len(checksum))
	}
}

func TestComputeChecksum_NonexistentFile(t *testing.T) {
	v := New()
	_, err := v.ComputeChecksum(context.Background(), "/nonexistent/file", SHA256)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestComputeChecksum_UnsupportedAlgorithm(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "verify-test-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	v := New()
	_, err = v.ComputeChecksum(context.Background(), tmpFile.Name(), Algorithm("md5"))
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestVerifyChecksum_Match(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "verify-test-*")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("verification test content")
	tmpFile.Write(content)
	tmpFile.Close()

	h := sha256.New()
	h.Write(content)
	expected := hex.EncodeToString(h.Sum(nil))

	v := New()
	result, err := v.VerifyChecksum(context.Background(), tmpFile.Name(), SHA256, expected)
	if err != nil {
		t.Fatalf("VerifyChecksum: %v", err)
	}

	if !result.Match {
		t.Error("expected checksum to match")
	}
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "verify-test-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Write([]byte("file content"))
	tmpFile.Close()

	v := New()
	result, err := v.VerifyChecksum(context.Background(), tmpFile.Name(), SHA256, "0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("VerifyChecksum: %v", err)
	}

	if result.Match {
		t.Error("expected checksum mismatch")
	}
}

func TestVerifyBaseline(t *testing.T) {
	dir := t.TempDir()

	file1 := dir + "/good.txt"
	file2 := dir + "/modified.txt"

	os.WriteFile(file1, []byte("good content"), 0o644)
	os.WriteFile(file2, []byte("modified content"), 0o644)

	h := sha256.New()
	h.Write([]byte("good content"))
	goodHash := hex.EncodeToString(h.Sum(nil))

	baseline := map[string]string{
		file1:                     goodHash,
		file2:                     "wrong_hash_on_purpose",
		dir + "/missing_file.txt": "doesnt_matter",
	}

	v := New()
	findings, err := v.VerifyBaseline(context.Background(), baseline)
	if err != nil {
		t.Fatalf("VerifyBaseline: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestSelfCheck_Mismatch(t *testing.T) {
	v := New()
	err := v.SelfCheck(context.Background(), "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Error("expected error for self-check mismatch")
	}
}
