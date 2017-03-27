package scanner

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

/*
 * The Scanner interface. This is meant as a starting point to support multiple
 * virus scanners. The concrete struct type is the Engine, that should then be
 * embedded in the scanner implementation. See scanner/clamav.go for the current
 * and only Scanner implementation.
 */
type Scanner interface {
	/*
	 * Sets the scanner engine address
	 */
	SetAddress(address string)

	/*
	 * Gets the scanner engine address
	 */
	Address() string

	/*
	 * This function sets the logger and whether debug
	 * is enabled or not
	 */
	SetLogger(logger *log.Logger, debug bool)

	/*
	 * This function performs the actual virus scan and returns a boolean indicating
	 * whether a virus has been found or not
	 */
	HasVirus(reader io.Reader) (bool, error)

	/*
	 * This function performs the actual virus scan and returns an engine-specific
	 * response string
	 */
	Scan(reader io.Reader) (*Result, error)

	/*
	 * Tests the liveliness of the underlying scan engine
	 */
	Ping() error

	/*
	 * Returns the version of the underlying scan engine
	 */
	Version() (string, error)
}

/*
 * A scanning engine, that is referenced via an address and has a logger and
 * a "debugging enabled" flag. The address is meant to be interpreted by the
 * specific scanner implementation.
 */
type Engine struct {
	Scanner
	address string
	logger  *log.Logger
	debug   bool
}

/*
 * Sets the engine address. It is provided also as a mean to perform further
 * initialisation or validation.
 */
func (e *Engine) SetAddress(address string) {
	e.address = address
}

/*
 * Returns the engine address.
 */
func (e *Engine) Address() string {
	return e.address
}

/*
 * Sets the logger object and whether debugging is enabled.
 */
func (e *Engine) SetLogger(logger *log.Logger, debug bool) {
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}
	e.logger = logger
	e.debug = debug
}

/*
 * Scanner result statuses
 */
const (
	RES_CLEAN = "CLEAN"
	RES_FOUND = "FOUND"
	RES_ERROR = "ERROR"
)

/*
 * Embeds a scan result.
 *
 * Status is one of the RES_* constants
 * Virus is true or false depending a Virus has been detected
 * Description is an extended status, containing the virus name
 */
type Result struct {
	Status      string
	Virus       bool
	Description string
}

func (r *Result) String() string {
	ret := fmt.Sprintf("Status: %s; Virus: %v", r.Status, r.Virus)

	if r.Virus {
		ret += fmt.Sprintf("; Description: %s", r.Description)
	}

	return ret
}
