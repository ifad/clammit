package main

import (
	"io"

	clamd "github.com/dutchcoders/go-clamd"
)

/*
 * The Scanner interface.
 */
type Scanner interface {

	/*
	 * This function performs the actual virus scan
	 */
	scan(reader io.Reader) (bool, error)
}

/*
 * ClamScanner scans files using clamav
 */
type ClamScanner struct {
	ClamdURL string
}

func (s ClamScanner) scan(reader io.Reader) (bool, error) {

	clam := clamd.NewClamd(s.ClamdURL)

	if ctx.Config.App.Debug {
		ctx.Logger.Println("Sending to clamav")
	}

	response, err := clam.ScanStream(reader)
	if err != nil {
		return false, err
	}

	hasVirus := false
	for s := range response {
		if s != "stream: OK" {
			if ctx.Config.App.Debug {
				ctx.Logger.Printf("  %v", s)
			}
			hasVirus = true
		}
	}

	if ctx.Config.App.Debug {
		ctx.Logger.Println("  result of scan:", hasVirus)
	}

	return hasVirus, nil
}
