/*
 * The Clammit application intercepts HTTP POST requests with content-type
 * "multipart/form-data", forwards any "file" form-data elements to ClamAV
 * and only forwards the request to the application if ClamAV passes all
 * of these elements as virus-free.
 */
package main

import (
	clamd "github.com/dutchcoders/go-clamd"
	"code.google.com/p/gcfg"
	"clammit/forwarder"
	"net/http"
	"net/url"
	"encoding/json"
	"mime"
	"mime/multipart"
	"log"
	"flag"
	"bytes"
	"io"
	"fmt"
	"os"
)

//
// Configuration structure, designed for gcfg
//
type Config struct {
	App ApplicationConfig      `gcfg:"application"`
}

type ApplicationConfig struct {
	Listen string              `gcfg:"listen"`
	ApplicationURL string      `gcfg:"application-url"`
	ClamdURL string            `gcfg:"clamd-url"`
	Logfile string             `gcfg:"log-file"`
	TestPages bool             `gcfg:"test-pages"`
}

//
// The implementation of the ClamAV interceptor
//
type ClamInterceptor struct {
	ClamdURL string
}

//
// Application context
//
type Ctx struct {
	Config Config
	ApplicationURL *url.URL
	ClamInterceptor *ClamInterceptor
	Logger *log.Logger
}

//
// JSON server information response
//
type Info struct {
	ClamdURL string            `json:"clam_server_url"`
	PingResult string          `json:"ping_result"`
	Version string             `json:"version"`
	TestScanVirusResult string `json:"test_scan_virus"`
	TestScanCleanResult string `json:"test_scan_clean"`
}

//
// Global variables and config
//
var ctx *Ctx
var configFile string

func init() {
	flag.StringVar( &configFile, "config", "", "Configuration file" )
}

func main() {
	/*
	 * Construct configuration, set up logging
	 */
	flag.Parse()
	ctx = &Ctx{}

	if configFile == "" {
		log.Fatal( "No configuration file specified" )
	}
	if err := gcfg.ReadFileInto( &ctx.Config, configFile ); err != nil {
		log.Fatal( "Configuration read failure:", err )
	}

	ctx.Logger = log.New( os.Stdout, "", log.LstdFlags )
	if ctx.Config.App.Logfile != "" {
		w, err := os.OpenFile( ctx.Config.App.Logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660 )
		if err == nil {
			ctx.Logger = log.New( w, "", log.LstdFlags )
		} else {
			log.Fatal( "Failed to open log file", ctx.Config.App.Logfile, ":", err )
		}
	}

	/*
	 * Construct objects, validate the URLs
	 */
	ctx.ApplicationURL = checkURL( ctx.Config.App.ApplicationURL )
	checkURL( ctx.Config.App.ClamdURL )

	ctx.ClamInterceptor =  &ClamInterceptor{ ClamdURL: ctx.Config.App.ClamdURL }

	/*
	 * Set up the HTTP server
	 */
	if ctx.Config.App.TestPages {
		fs := http.FileServer( http.Dir( "testfiles" ) )
		http.Handle( "/test/", http.StripPrefix( "/test/",  fs ) )
	}
	http.HandleFunc( "/scan", scanHandler )
	http.HandleFunc( "/scanforward", scanForwardHandler )
	http.HandleFunc( "/info", infoHandler )
	ctx.Logger.Println( "Listening on", ctx.Config.App.Listen )
	ctx.Logger.Fatal( http.ListenAndServe( ctx.Config.App.Listen, nil ) )
}

/*
 * Validates the URL is OK (fatal error if not) and returns it
 */
func checkURL( urlString string ) *url.URL {
	parsedURL, err := url.Parse( urlString )
	if err != nil {
		log.Fatal( "Invalid URL:", urlString )
	}
	return parsedURL
}

/*
 * Handler for /scan
 *
 * Virus checks file and sends response
 */
func scanHandler( w http.ResponseWriter, req *http.Request ) {
	fw := forwarder.NewForwarder( ctx.ApplicationURL, ctx.ClamInterceptor )
	fw.SetLogger( ctx.Logger )
	fw.HandleRequest( w, req, false )
}

/*
 * Handler for /scanforward
 *
 * Constructs a forwarder and calls it
 */
func scanForwardHandler( w http.ResponseWriter, req *http.Request ) {
	fw := forwarder.NewForwarder( ctx.ApplicationURL, ctx.ClamInterceptor )
	fw.SetLogger( ctx.Logger )
	fw.HandleRequest( w, req, true )
}

/*
 * Handler for /info
 *
 * Validates the Clamd connection
 * Emits the information as a JSON response
 */
func infoHandler( w http.ResponseWriter, req *http.Request ) {
	c := clamd.NewClamd( ctx.ClamInterceptor.ClamdURL )
	info := &Info{
		ClamdURL: ctx.ClamInterceptor.ClamdURL,
	}
	if err := c.Ping(); err != nil {
		// If we can't ping the Clamd server, no point in making the remaining requests
		info.PingResult = err.Error()
	} else {
		info.PingResult = "Connected to server OK"
		if response, err := c.Version(); err != nil {
			info.Version = err.Error();
		} else {
			for s := range response {
				info.Version += s
			}
		}
		/*
		 * Validate the Clamd response for a viral string
		 */
		reader := bytes.NewReader( clamd.EICAR )
		if response, err := c.ScanStream( reader ); err != nil {
			info.TestScanVirusResult = err.Error()
		} else {
			for s := range response {
				info.TestScanVirusResult += s
			}
		}
		/*
		 * Validate the Clamd response for a non-viral string
		 */
		reader = bytes.NewReader( []byte("foo bar mcgrew") )
		if response, err := c.ScanStream( reader ); err != nil {
			info.TestScanCleanResult = err.Error()
		} else {
			for s := range response {
				info.TestScanCleanResult += s
			}
		}
	}
	// Aaaand return
	s, _ := json.Marshal(info)
	w.Header().Set("Content-Type", "application/json")
	w.Write( []byte(s) )
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
	// Find any attachments
	//
	_, params, err := mime.ParseMediaType( req.Header.Get( "Content-Type" ) )
	if err != nil {
		return false
	}
	boundary := params["boundary"]
	if boundary == "" {
		return false
	}

	reader := multipart.NewReader( body, boundary )

	//
	// Scan them
	//
	var broken_err error

	for {
		if part, err := reader.NextPart(); err != nil {
			break // all done
		} else {
			if part.FileName() != "" {
				defer part.Close()
				ctx.Logger.Println( "Scanning",part.FileName() )
				if hasVirus, err := c.Scan( part ); err != nil {
					broken_err = err
				} else if hasVirus {
					w.WriteHeader( 418 )
					w.Write( []byte(fmt.Sprintf( "File %s has a virus!", part.FileName() ) ) )
					return true
				}
			}
		}
	}

	//
	// If failure, we bomb out here
	//
	if broken_err != nil {
		w.WriteHeader( 500 )
		w.Write( []byte(fmt.Sprintf( "Unable to scan a file: %s", broken_err.Error()) ) )
		return true
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
			ctx.Logger.Printf("%v %v\n", s )
			hasVirus = true
		}
	}

	ctx.Logger.Println( "Result of scan:", hasVirus )

	return hasVirus, nil
}
