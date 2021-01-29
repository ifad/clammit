package scanner

import (
	clamd "github.com/dutchcoders/go-clamd"
	"io"
)

/*
 * Clamav scans files using clamav
 */
type Clamav struct {
	Engine
	clam *clamd.Clamd
}

func (c *Clamav) SetAddress(url string) {
	c.Engine.SetAddress(url)
	c.clam = clamd.NewClamd(url)

	if c.debug {
		c.logger.Println("Initialised clamav connection to", url)
	}
}

func (c *Clamav) HasVirus(reader io.Reader) (bool, error) {
	result, err := c.Scan(reader)
	if err != nil {
		return false, err
	}

	return result.Virus, nil
}

func (c *Clamav) Scan(reader io.Reader) (*Result, error) {
	if c.debug {
		c.logger.Println("Sending to clamav")
	}

	ch, err := c.clam.ScanStream(reader, nil)
	if err != nil {
		return nil, err
	}
	var status string

	r := (<-ch)

	switch r.Status {
	case clamd.RES_OK:
		status = RES_CLEAN
	case clamd.RES_FOUND:
		status = RES_FOUND
	case clamd.RES_ERROR:
	case clamd.RES_PARSE_ERROR:
	default:
		status = RES_ERROR
	}

	result := &Result{
		Status:      status,
		Virus:       status == RES_FOUND,
		Description: r.Description,
	}

	if c.debug {
		c.logger.Println("  result of scan:", result)
	}

	return result, nil
}

func (c *Clamav) Ping() error {
	return c.clam.Ping()
}

func (c *Clamav) Version() (string, error) {
	ch, err := c.clam.Version()
	if err != nil {
		return "", err
	}

	r := (<-ch)
	return r.Raw, nil
}
