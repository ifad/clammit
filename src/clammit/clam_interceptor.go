/*
 * The Clammit application intercepts HTTP POST requests with content-type
 * "multipart/form-data", forwards any "file" form-data elements to ClamAV
 * and only forwards the request to the application if ClamAV passes all
 * of these elements as virus-free.
 */
package main

import (
	clamd "github.com/dutchcoders/go-clamd"
	"net/http"
	"mime"
	"mime/multipart"
	"io"
	"fmt"
)

//
// The implementation of the ClamAV interceptor
//
type ClamInterceptor struct {
    ClamdURL string
	VirusStatusCode int
}

/*
 * Interceptor implementation for Clamd
 *
 * Runs a multi-part parser across the request body and sends all file contents to Clamd
 *
 * returns True if the body contains a virus
 */
func (c *ClamInterceptor) Handle( w http.ResponseWriter, req *http.Request, body io.Reader ) bool {
	//
	// Don't care unless it's a post
	//
	if req.Method != "POST" && req.Method != "PUT" && req.Method != "PATCH" {
		ctx.Logger.Println( "No need to handle method", req.Method )
		return false
	}

	//
	// Find any attachments
	//
	content_type, params, err := mime.ParseMediaType( req.Header.Get( "Content-Type" ) )
	if err != nil {
		ctx.Logger.Println( "Unable to parse media type:", err )
		return false
	}
	if content_type != "multipart/form-data" {
		ctx.Logger.Println( "Content type is not multipart/form-data: ", content_type )
		return false
	}
	boundary := params["boundary"]
	if boundary == "" {
		ctx.Logger.Println( "Multipart boundary is not defined" )
		return false
	}

	reader := multipart.NewReader( body, boundary )

	//
	// Scan them
	//
	for {
		if part, err := reader.NextPart(); err != nil {
			if err == io.EOF {
				break // all done
			}
			ctx.Logger.Println( "Error parsing multipart form:", err )
			w.WriteHeader( 500 )
			w.Write( []byte(fmt.Sprintf( "Error parsing multipart form: %v", err )) )
			return true
		} else {
			if part.FileName() != "" {
				defer part.Close()
				ctx.Logger.Println( "Scanning",part.FileName() )
				if hasVirus, err := c.Scan( part ); err != nil {
					w.WriteHeader( 500 )
					w.Write( []byte(fmt.Sprintf( "Unable to scan a file (%s): %v", part.FileName(), err)) )
					return true
				} else if hasVirus {
					w.WriteHeader( c.VirusStatusCode )
					w.Write( []byte(fmt.Sprintf( "File %s has a virus!", part.FileName() ) ) )
					return true
				}
			}
		}
	}

	return false
}

/*
 * This function performs the actual virus scan
 */
func (c *ClamInterceptor) Scan( reader io.Reader ) (bool, error) {

	clam := clamd.NewClamd( c.ClamdURL )

	response, err := clam.ScanStream( reader )
	if err != nil {
		return false, err
	}
	hasVirus := false
	for s := range response {
		if s != "stream: OK" {
			ctx.Logger.Printf("%v", s )
			hasVirus = true
		}
	}

	ctx.Logger.Println( "Result of scan:", hasVirus )

	return hasVirus, nil
}
