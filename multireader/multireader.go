package multireader

import (
	"bytes"
	"fmt"
	"io"
)

type MultiReader struct {
	*bytes.Buffer
}

func New(input io.Reader, contentLength int64) (*MultiReader, error) {
	if contentLength <= 0 {
		return nil, fmt.Errorf("Invalid content length: %d", contentLength)
	}
	mb := &MultiReader{bytes.NewBuffer(make([]byte, 0))}
	if count, err := io.Copy(mb, input); err != nil {
		return nil, err
	} else if count != contentLength {
		return nil, fmt.Errorf("Byte read mismatch - expected %d, read %d", contentLength, count)
	} else {
		return mb, nil
	}
}

func (m *MultiReader) ContentLength() int64 {
	return int64(len(m.Bytes()))
}

func (m *MultiReader) GetReadCloser() (io.ReadCloser, error) {
	return &multiReaderCursor{bytes.NewReader(m.Bytes())}, nil
}

func (m *MultiReader) Close() error {
	return nil
}

type multiReaderCursor struct {
	*bytes.Reader
}

func (m *multiReaderCursor) Close() error {
	return nil
}
