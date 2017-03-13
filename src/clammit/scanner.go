package main

import (
	"io"

	clamd "github.com/dutchcoders/go-clamd"
)
var EICAR = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

/*
 * The Scanner interface.
 */
type Scanner interface {

	/*
	 * This function performs the actual virus scan
	 */
	hasVirus(reader io.Reader) (bool, error)

	/*
	 * This function performs the actual virus scan
	 */
	scan(reader io.Reader) (chan string, error)

	/*
	 * Tests the liveliness of the underlying scan engine
	 */
	ping() error

	/*
	 * Returns the version of the underlying scan engine
	 */
	version() (chan string, error)
}

/*
 * ClamScanner scans files using clamav
 */
type ClamScanner struct {
	ClamdURL string
}

func (s ClamScanner) hasVirus(reader io.Reader) (bool, error) {

	response, err := s.scan(reader)
	if err != nil {
		return false, err
	}

	result := false
	for s := range response {
		if s != "stream: OK" {
			if ctx.Config.App.Debug {
				ctx.Logger.Printf("  %v", s)
			}
			result = true
		}
	}

	if ctx.Config.App.Debug {
		ctx.Logger.Println("  result of scan:", result)
	}

	return result, nil
}

func (s ClamScanner) scan(reader io.Reader) (chan string, error) {

	clam := clamd.NewClamd(s.ClamdURL)

	if ctx.Config.App.Debug {
		ctx.Logger.Println("Sending to clamav")
	}

	return  clam.ScanStream(reader)
}

func (s ClamScanner) ping() error {
	c := clamd.NewClamd(s.ClamdURL)
	return c.Ping()
}

func (s ClamScanner) version() (chan string, error) {
	c := clamd.NewClamd(s.ClamdURL)
	return c.Version()
}
