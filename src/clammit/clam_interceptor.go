/*
 * The Clammit application intercepts HTTP POST requests including content-type
 * "multipart/form-data", forwards any "file" form-data elements to ClamAV
 * and only forwards the request to the application if ClamAV passes all
 * of these elements as virus-free.
 */
package main

import (
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"

	clamd "github.com/dutchcoders/go-clamd"
)

//
// The implementation of the ClamAV interceptor
//
type ClamInterceptor struct {
	ClamdURL        string
	VirusStatusCode int
}

/*
 * Interceptor implementation for Clamd
 *
 * Runs a multi-part parser across the request body and sends all file contents to Clamd
 *
 * returns True if the body contains a virus
 */
func (c *ClamInterceptor) Handle(w http.ResponseWriter, req *http.Request, body io.Reader) bool {
	//
	// Don't care unless it's a post
	//
	if req.Method != "POST" && req.Method != "PUT" && req.Method != "PATCH" {
		if ctx.Config.App.Debug {
			ctx.Logger.Println("No need to handle method", req.Method)
		}
		return false
	}

	ctx.Logger.Printf("New request %s %s from %s (%s)\n", req.Method, req.URL.Path, req.RemoteAddr, req.Header.Get("X-Forwarded-For"))

	//
	// Find any attachments
	//
	contentType, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		ctx.Logger.Println("Unable to parse media type:", err)
		return false
	}

	if contentType == "multipart/form-data" {
		boundary := params["boundary"]
		if boundary == "" {
			ctx.Logger.Println("Multipart boundary is not defined")
			return false
		}

		reader := multipart.NewReader(body, boundary)

		//
		// Scan them
		//
		count := 0
		for {
			if part, err := reader.NextPart(); err != nil {
				if err == io.EOF {
					break // all done
				}
				ctx.Logger.Println("Error parsing multipart form:", err)
				http.Error(w, "Bad Request", 400)
				return true
			} else {
				count++
				filename := part.FileName()
				if filename == "" {
					filename = "untitled"
				}
				defer part.Close()
				if ctx.Config.App.Debug {
					ctx.Logger.Println("Scanning", part.FileName())
				}
				if responded := c.respondOnVirus(w, filename, part); responded == true {
					return true
				}
			}
		}
		if ctx.Config.App.Debug {
			ctx.Logger.Printf("Processed %d form parts", count)
		}
	} else {
		filename := "untitled"
		_, params, err := mime.ParseMediaType(req.Header.Get("Content-Disposition"))
		if err == nil {
			filename = params["filename"]
		}
		return c.respondOnVirus(w, filename, body)
	}
	return false
}

/*
 * This function performs the virus scan and handles the http response in case of a virus.
 *
 * returns True if a virus has been found and a http error response has been written
 */
func (c *ClamInterceptor) respondOnVirus(w http.ResponseWriter, filename string, reader io.Reader) bool {
	if hasVirus, err := c.scan(reader); err != nil {
		ctx.Logger.Printf("Unable to scan file (%s): %v\n", filename, err)
		http.Error(w, "Internal Server Error", 500)
		return true
	} else if hasVirus {
		w.WriteHeader(c.VirusStatusCode)
		w.Write([]byte(fmt.Sprintf("File %s has a virus!", filename)))
		return true
	}
	return false
}

/*
 * This function performs the actual virus scan
 */
func (c *ClamInterceptor) scan(reader io.Reader) (bool, error) {

	clam := clamd.NewClamd(c.ClamdURL)

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
