/*
 * This is a simple package to construct (and eventually remove) a scratch directory,
 * so that all files are held in this temporary area.
 */
package scratch

import (
	"io/ioutil"
	"os"
)

type ScratchArea struct {
	TempDir string
}

/*
 * Constructs a new scratch area, in the given base directory, prefixed as appropriate.
 */
func NewScratchArea(tempdir string, name string) (*ScratchArea, error) {
	if name == "" {
		name = "scratch"
	}
	if tempDir, err := ioutil.TempDir(tempdir, name); err != nil {
		return nil, err
	} else {
		return &ScratchArea{TempDir: tempDir}, nil
	}
}

/*
 * Deletes the scratch area
 */
func (s *ScratchArea) Cleanup() {
	_ = os.RemoveAll(s.TempDir)
}

/*
 * Creates a new file in the scratch area and returns a handle to it
 */
func (s *ScratchArea) NewFile(prefix string) (*os.File, error) {
	if prefix == "" {
		prefix = "scratch"
	}
	return ioutil.TempFile(s.TempDir, prefix)
}
