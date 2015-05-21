package forwarder

import (
	"io"
	"os"
	"clammit/multireader"
	"clammit/scratch"
)

const (
	CONTENT_LENGTH = 1024 * 1024 // 1MB
)

type BodyHolder interface {
	ContentLength() int64
	GetReadCloser() (io.ReadCloser, error)
	Close() error
}

func NewBodyHolder( input io.Reader, contentLength int64, maxContentLength int64 ) (BodyHolder, error) {
	if contentLength == 0 || contentLength > maxContentLength {
		return newFileBodyHolder( input )
	} else {
		return multireader.New( input, contentLength )
	}
}

type fileBodyHolder struct {
	scratchArea *scratch.ScratchArea
	bodyFilename string
	contentLength int64
}

func newFileBodyHolder( input io.Reader ) (BodyHolder, error) {
	sa, err := scratch.NewScratchArea( "", "clammit" )
	if err != nil {
		sa.Cleanup()
		return nil, err
	}
	fb := &fileBodyHolder{ scratchArea: sa  }
	bodyFile, err := sa.NewFile( "body" )
	if err != nil {
		sa.Cleanup()
		return nil, err
	}
	defer bodyFile.Close()
	count, err := io.Copy( bodyFile, input )
	if err != nil {
		sa.Cleanup()
		return nil, err
	}
	fb.bodyFilename = bodyFile.Name()
	fb.contentLength = count
	return fb, nil
}

func (f *fileBodyHolder) GetReadCloser() (io.ReadCloser, error) {
	return os.Open( f.bodyFilename )
}

func (f *fileBodyHolder) Close() error {
	f.scratchArea.Cleanup()
	return nil
}

func (f *fileBodyHolder) ContentLength() int64 {
	return f.contentLength
}
