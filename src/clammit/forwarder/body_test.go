package forwarder

import (
	"bytes"
	"io"
	"testing"
)

func TestFileBodyHolder(t *testing.T) {
	s := "This is a brown fox, doggy"
	input := bytes.NewReader([]byte(s))
	length := int64(len([]byte(s)))

	holder, err := NewBodyHolder(input, length, 1000)
	if err != nil {
		t.Fatal("Unexpected error constructing memBodyHolder", err)
	}
	defer holder.Close()
	if holder.ContentLength() != length {
		t.Fatalf("memBodyHolder.ContentLength() incorrect. Expected %d, got %d", length, holder.ContentLength())
	}
	rc1, err := holder.GetReadCloser()
	if err != nil {
		t.Fatal("Unexpected error getting ReadClose()", err)
	}
	buf := bytes.NewBufferString("")
	if _, err := io.Copy(buf, rc1); err != nil {
		t.Fatal("Unexpected error writing buffer", err)
	}
	s1 := buf.String()
	if s1 != s {
		t.Fatalf("memBodyHolder.GetReadCloser() incorrect. Expected %s, got %s", s, s1)
	}
	if err := rc1.Close(); err != nil {
		t.Error("ReadCloser.Close() returned unexpected error:", err)
	}
}

func TestMemoryBodyHolder(t *testing.T) {
	s := "This is a brown fox, doggy"
	input := bytes.NewReader([]byte(s))
	length := int64(len([]byte(s)))

	holder, err := NewBodyHolder(input, length, 5)
	if err != nil {
		t.Fatal("Unexpected error constructing fileBodyHolder", err)
	}
	defer holder.Close()
	if holder.ContentLength() != length {
		t.Fatalf("fileBodyHolder.ContentLength() incorrect. Expected %d, got %d", length, holder.ContentLength())
	}
	rc1, err := holder.GetReadCloser()
	if err != nil {
		t.Fatal("Unexpected error getting ReadClose()", err)
	}
	buf := bytes.NewBufferString("")
	if _, err := io.Copy(buf, rc1); err != nil {
		t.Fatal("Unexpected error writing buffer", err)
	}
	s1 := buf.String()
	if s1 != s {
		t.Fatalf("fileBodyHolder.GetReadCloser() incorrect. Expected %s, got %s", s, s1)
	}
	if err := rc1.Close(); err != nil {
		t.Error("ReadCloser.Close() returned unexpected error:", err)
	}
}
