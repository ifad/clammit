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
	"net"
	"strings"
	"strconv"
	"net/http"
	"net/url"
	"encoding/json"
	"mime"
	"mime/multipart"
	"log"
	"flag"
	"bytes"
	"io"
	"io/ioutil"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

//
// Configuration structure, designed for gcfg
//
type Config struct {
	App ApplicationConfig      `gcfg:"application"`
}

type ApplicationConfig struct {
	Listen string              `gcfg:"listen"`
	SocketPerms string         `gcfg:"unix-socket-perms"`
	ApplicationURL string      `gcfg:"application-url"`
	ClamdURL string            `gcfg:"clamd-url"`
	Logfile string             `gcfg:"log-file"`
	TestPages bool             `gcfg:"test-pages"`
	Debug bool                 `gcfg:"debug"`
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
	Debug bool
	Listener net.Listener
	ActivityChan chan int
	ShuttingDown bool
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
	ctx = &Ctx{
		ActivityChan: make(chan int),
		ShuttingDown: false,
    }

	if configFile == "" {
		log.Fatal( "No configuration file specified" )
	}
	if err := gcfg.ReadFileInto( &ctx.Config, configFile ); err != nil {
		log.Fatal( "Configuration read failure:", err )
	}
	// Socket perms are octal!
	socketPerms := 0777
	if ctx.Config.App.SocketPerms != "" {
		if sp, err := strconv.ParseInt( ctx.Config.App.SocketPerms, 8, 0 ) ; err == nil {
			socketPerms = int(sp)
		}
	}

	startLogging()

	/*
	 * Construct objects, validate the URLs
	 */
	ctx.ApplicationURL = checkURL( ctx.Config.App.ApplicationURL )
	checkURL( ctx.Config.App.ClamdURL )

	ctx.ClamInterceptor =  &ClamInterceptor{ ClamdURL: ctx.Config.App.ClamdURL }

	/*
	 * Set up the HTTP server
	 */
	router := http.NewServeMux()

	router.HandleFunc( "/clammit", infoHandler )
	router.HandleFunc( "/clammit/scan", scanHandler )
	if ctx.Config.App.TestPages {
		fs := http.FileServer( http.Dir( "testfiles" ) )
		router.Handle( "/clammit/test/", http.StripPrefix( "/test/",  fs ) )
	}
	router.HandleFunc( "/", scanForwardHandler )

	log.SetOutput( ioutil.Discard ) // go-clamd has irritating logging, so turn it off

	if listener, err := getListener( ctx.Config.App.Listen, socketPerms ); err != nil {
		ctx.Logger.Fatal( "Unable to listen on: ", ctx.Config.App.Listen, ", reason: ", err )
	} else {
		ctx.Listener = listener
		beGraceful() // graceful shutdown from here on in
		ctx.Logger.Println( "Listening on", ctx.Config.App.Listen )
		http.Serve( listener, router )
	}
}

/*
 * Starts logging
 */
func startLogging() {
	ctx.Logger = log.New( os.Stdout, "", log.LstdFlags )
	if ctx.Config.App.Logfile != "" {
		w, err := os.OpenFile( ctx.Config.App.Logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660 )
		if err == nil {
			ctx.Logger = log.New( w, "", log.LstdFlags )
		} else {
			log.Fatal( "Failed to open log file", ctx.Config.App.Logfile, ":", err )
		}
	}
}

/*
 * Handles graceful shutdown. Sets ctx.ShuttingDown = true to stop any new
 * requests, then waits for active requests to complete before closing the
 * HTTP listener.
 */
func beGraceful() {
	sigchan := make(chan os.Signal)
	signal.Notify( sigchan, syscall.SIGINT, syscall.SIGTERM )
	go func() {
		activity := 0
		for {
			select {
				case _ = <-sigchan:
					ctx.Logger.Println( "Received termination signal" )
					ctx.ShuttingDown = true
					for activity > 0 {
						ctx.Logger.Printf( "There are %d active requests, waiting", activity )
						i := <-ctx.ActivityChan
						activity += i
					}
					// This will cause main() to continue from http.Serve()
					// it will also clean up the unix socket (if relevant)
					ctx.Listener.Close()
				case i := <-ctx.ActivityChan:
					activity += i
			}
		}
	}()
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
 * Returns a TCP or Unix socket listener, according to the scheme prefix:
 *
 *   unix:/tmp/foo.sock
 *   tcp::8438
 *   :8438                 - tcp listener
 */
func getListener( address string, socketPerms int ) (listener net.Listener, err error) {
	if address == "" {
		return nil, fmt.Errorf( "No listen address specified" )
	}
	if idx := strings.Index( address, ":" ); idx >= 0 {
		scheme := address[0:idx]
		switch scheme {
			case "tcp", "tcp4" :
				path := address[idx+1:]
				if strings.Index(path,":") == -1 {
					path = ":" + path
				}
				listener, err = net.Listen( scheme, path )
			case "tcp6" : // general form: [host]:port
				path := address[idx+1:]
				if strings.Index(path,"[") != 0 { // port only
					if strings.Index(path,":") != 0 { // no leading :
						path = ":" + path
					}
				}
				listener, err = net.Listen( scheme, path )
			case "unix", "unixpacket" :
				path := address[idx+1:]
				if listener, err = net.Listen( scheme, path ); err == nil {
					os.Chmod( path, os.FileMode(socketPerms) )
				}
			default : // assume TCP4 address
				listener, err = net.Listen( "tcp", address )
		}
	} else { // no scheme, port only specified
		listener, err = net.Listen( "tcp", ":" + address )
	}
	return listener, err
}

/*
 * Handler for /scan
 *
 * Virus checks file and sends response
 */
func scanHandler( w http.ResponseWriter, req *http.Request ) {
	if ctx.ShuttingDown {
		return
	}
	ctx.ActivityChan <- 1
	defer func() { ctx.ActivityChan <- -1 }()

	if ! ctx.ClamInterceptor.Handle( w, req, req.Body ) {
		w.Write( []byte("No virus found") )
	}
}

/*
 * Handler for scan & forward
 *
 * Constructs a forwarder and calls it
 */
func scanForwardHandler( w http.ResponseWriter, req *http.Request ) {
	if ctx.ShuttingDown {
		return
	}
	ctx.ActivityChan <- 1
	defer func() { ctx.ActivityChan <- -1 }()

	fw := forwarder.NewForwarder( ctx.ApplicationURL, ctx.ClamInterceptor )
	fw.SetLogger( ctx.Logger )
	fw.HandleRequest( w, req )
}

/*
 * Handler for /info
 *
 * Validates the Clamd connection
 * Emits the information as a JSON response
 */
func infoHandler( w http.ResponseWriter, req *http.Request ) {
	if ctx.ShuttingDown {
		return
	}
	ctx.ActivityChan <- 1
	defer func() { ctx.ActivityChan <- -1 }()

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
	// Don't care unless it's a post
	//
	if req.Method != "POST" && req.Method != "PUT" {
		return false
	}

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
