package scratch

import (
	"os"
	"testing"
)

func TestScratchArea(t *testing.T) {
	tempDir := "."
	sa, err := NewScratchArea(tempDir, "temp")
	if err != nil {
		t.Fatalf("Failed to create scratch area: %s", err.Error())
	}
	if sa.TempDir == "" {
		t.Fatalf("TempDir was not set")
	}
	_, err = os.Stat(sa.TempDir)
	if err != nil {
		t.Fatalf("Stat of %s failed: %s", sa.TempDir, err.Error())
	}
	file, err := sa.NewFile("foo")
	if err != nil {
		t.Fatalf("NewFile() failed: %s", err.Error())
	}
	file.Write([]byte("This is a good thing"))
	file.Close()
	sa.Cleanup()
	_, err = os.Stat(sa.TempDir)
	if err == nil {
		t.Fatalf("Cleanup() failed, tempdir still exists")
	}
}
