package multireader

import (
	"bytes"
	"testing"
)

func TestMultiReader(t *testing.T) {
	s := "Browning the fox quickly"
	input := bytes.NewBufferString(s)
	length := len(input.Bytes())
	//
	// Construct a new MultiBuf
	//
	mb, err := New(input, int64(length))
	if err != nil {
		t.Fatal("New() gave error:", err)
	}
	if mb.ContentLength() != int64(length) {
		t.Fatalf("ContentLength mismatch, expected %d, got %d", length, mb.ContentLength())
	}
	//
	// Check that we can read the thing
	//
	result := make([]byte, length)
	mc1, _ := mb.GetReadCloser()
	count, err := mc1.Read(result)
	if err != nil {
		t.Fatal("Read() #1 gave error:", err)
	}
	if count != length {
		t.Fatalf("Read() #1 only gave %d bytes, expected: %d", count, length)
	}
	if string(result) != s {
		t.Fatalf("Read() #1 gave: '%s', expected: '%s'", string(result), s)
	}
	if err = mc1.Close(); err != nil {
		t.Fatalf("Close() #1 failed. Hell, that should NOT be possible")
	}
	//
	// The second one should give the same results as the first
	//
	mc2, _ := mb.GetReadCloser()
	_, err = mc2.Read(result)
	if err != nil {
		t.Fatal("Read() #2 gave error:", err)
	}
	if string(result) != s {
		t.Fatalf("Read() #2 gave: '%s', expected: '%s'", string(result), s)
	}
}
