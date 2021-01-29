package forwarder

import (
	"clammit/multireader"
	"clammit/scratch"
	"io"
	"os"
)

const (
	CONTENT_LENGTH = 1024 * 1024 // 1MB
)

/*
 * This is an abstraction of a local copy of the request body, which could be
 * stored in memory or on disk. This allows for multiple accesses to the
 * content, rather than the single pass you're allowed with io.Reader.
 *
 * In general usage terms:
 *
 *   func HandleRequest( w http.ResponseWriter, req *http.Request ) {
 *     ...
 *     if req.Body != nil {
 *       defer req.Body.Close()
 *       holder, err := NewBodyHolder( req.Body, req.ContentLength, 100000 )
 *       if err != nil {
 *         return
 *       }
 *       defer holder.Close()
 *       reader, err := holder.GetReadCloser()
 *       if err != nil {
 *         return
 *       }
 *       defer reader.Close()
 *       ...
 *     }
 *   }
 */
type BodyHolder interface {
	// Number of bytes in the body
	ContentLength() int64
	// Returns a ReadCloser on the body
	GetReadCloser() (io.ReadCloser, error)
	// Allows the BodyHolder to clean itself up - you should call this
	// once done.
	Close() error
}

/*
 * Constructs a local copy of the request body. Depending on contentLength, it
 * will be either in memory or on disk. If contentLength is 0 (i.e. chunked
 * transfer) the body will be saved to disk. Be aware that the input will be
 * read to construct the BodyHolder, so you will not be able to perform any
 * more operations on it afterwards and you should Close() it (if possible).
 */
func NewBodyHolder(input io.Reader, contentLength int64, maxContentLength int64) (BodyHolder, error) {
	if contentLength == 0 || contentLength > maxContentLength {
		return newFileBodyHolder(input)
	} else {
		return multireader.New(input, contentLength)
	}
}

/*
 * File storage version of the BodyHolder
 */
type fileBodyHolder struct {
	scratchArea   *scratch.ScratchArea
	bodyFilename  string
	contentLength int64
}

/*
 * Constructs a new fileBodyHolder - it uses the scratch.ScratchArea to store
 * the file.
 */
func newFileBodyHolder(input io.Reader) (BodyHolder, error) {
	sa, err := scratch.NewScratchArea("", "clammit")
	if err != nil {
		sa.Cleanup()
		return nil, err
	}
	fb := &fileBodyHolder{scratchArea: sa}
	bodyFile, err := sa.NewFile("body")
	if err != nil {
		sa.Cleanup()
		return nil, err
	}
	defer bodyFile.Close()
	count, err := io.Copy(bodyFile, input)
	if err != nil {
		sa.Cleanup()
		return nil, err
	}
	fb.bodyFilename = bodyFile.Name()
	fb.contentLength = count
	return fb, nil
}

/*
 * Implementation of BodyHolder.GetReadCloser().
 */
func (f *fileBodyHolder) GetReadCloser() (io.ReadCloser, error) {
	return os.Open(f.bodyFilename)
}

/*
 * Implementation of BodyHolder.Close().
 */
func (f *fileBodyHolder) Close() error {
	f.scratchArea.Cleanup()
	return nil
}

/*
 * Implementation of BodyHolder.ContentLength().
 */
func (f *fileBodyHolder) ContentLength() int64 {
	return f.contentLength
}
