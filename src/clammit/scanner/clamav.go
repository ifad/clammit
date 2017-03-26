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
		c.logger.Println("Initialised clamav connection to %s", url)
	}
}

func (c *Clamav) HasVirus(reader io.Reader) (bool, error) {
	response, err := c.Scan(reader)
	if err != nil {
		return false, err
	}

	result := false
	for s := range response {
		if s != "stream: OK" {
			if c.debug {
				c.logger.Printf("  %v", s)
			}
			result = true
		}
	}

	if c.debug {
		c.logger.Println("  result of scan:", result)
	}

	return result, nil
}

func (c *Clamav) Scan(reader io.Reader) (chan string, error) {
	if c.debug {
		c.logger.Println("Sending to clamav")
	}

	return c.clam.ScanStream(reader)
}

func (c *Clamav) Ping() error {
	return c.clam.Ping()
}

func (c *Clamav) Version() (chan string, error) {
	return c.clam.Version()
}
