/*
 * The Clammit application intercepts HTTP POST requests with content-type
 * "multipart/form-data", forwards any "file" form-data elements to ClamAV
 * and only forwards the request to the application if ClamAV passes all
 * of these elements as virus-free.
 */
package main

import (
	"bytes"
	"clammit/forwarder"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	clamd "github.com/dutchcoders/go-clamd"
	"gopkg.in/gcfg.v1"
)

//
// Configuration structure, designed for gcfg
//
type Config struct {
	App ApplicationConfig `gcfg:"application"`
}

type ApplicationConfig struct {
	// The address to listen on. This can be one of:
	// * tcp:host:port
	// * tcp:port
	// * unix:filename
	// * host:port
	// * :port
	//
	// For example:
	//   Listen: tcp:0.0.0.0:8438
	//   Listen: unix:/tmp/clammit.sock
	//   Listen: :8438
	Listen string `gcfg:"listen"`
	// Socket file permissions (only used if listening on a unix socket), in octal form.
	//
	// For example:
	//   SocketPerms: 0766
	SocketPerms string `gcfg:"unix-socket-perms"`
	// The URL of the application that Clammit is proxying. Generally, this will
	// be the base URL (http://host:port/), but you can also add a path prefix
	// if needed (http://host:port/prefix)
	ApplicationURL string `gcfg:"application-url"`
	// The URL of clamd, which will either be TCP or Unix:
	//
	// For example:
	//   ClamdURL: tcp://localhost:3310
	//   ClamdURL: unix:/tmp/clamd.sock
	ClamdURL string `gcfg:"clamd-url"`
	// The HTTP status code to return when a virus is found
	VirusStatusCode int `gcfg:"virus-status-code"`
	// If the body content-length exceeds this value, it will be written to
	// disk. Below it, we'll hold the whole body in memory to improve speed.
	ContentMemoryThreshold int64 `gcfg:"content-memory-threshold"`
	// Log file name (default is to log to stdout)
	Logfile string `gcfg:"log-file"`
	// If true, clammit will expose a small test HTML page.
	TestPages bool `gcfg:"test-pages"`
	// If true, will log the progression of each request through the forwarder
	Debug bool `gcfg:"debug"`
	// If true, will log the annoying clamd messages
	DebugClam bool `gcfg:"debug-clam"`
	// Number of CPU threads to use
	NumThreads int `gcfg:"num-threads"`
}

//
// Default configuration
//
var DefaultApplicationConfig = ApplicationConfig{
	Listen:                 ":8438",
	SocketPerms:            "0777",
	ApplicationURL:         "",
	ClamdURL:               "",
	VirusStatusCode:        418,
	ContentMemoryThreshold: 1024 * 1024,
	Logfile:                "",
	TestPages:              true,
	Debug:                  false,
	DebugClam:              false,
	NumThreads:             runtime.NumCPU(),
}

//
// Application context
//
type Ctx struct {
	Config          Config
	ApplicationURL  *url.URL
	ClamInterceptor *ClamInterceptor
	Logger          *log.Logger
	Listener        net.Listener
	ActivityChan    chan int
	ShuttingDown    bool
}

//
// JSON server information response
//
type Info struct {
	ClamdURL            string `json:"clam_server_url"`
	PingResult          string `json:"ping_result"`
	Version             string `json:"version"`
	TestScanVirusResult string `json:"test_scan_virus"`
	TestScanCleanResult string `json:"test_scan_clean"`
}

//
// Global variables and config
//
var ctx *Ctx
var configFile string

func init() {
	flag.StringVar(&configFile, "config", "", "Configuration file")
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

	ctx.Config.App = DefaultApplicationConfig

	if err := gcfg.ReadFileInto(&ctx.Config, configFile); err != nil {
		log.Fatalf("Configuration read failure: %s", err.Error())
	}

	// Socket perms are octal!
	socketPerms := 0777
	if ctx.Config.App.SocketPerms != "" {
		if sp, err := strconv.ParseInt(ctx.Config.App.SocketPerms, 8, 0); err == nil {
			socketPerms = int(sp)
		} else {
			log.Fatalf("SocketPerms invalid (expected 4-digit octal: %s", err.Error)
		}
	}

	// Allow multi-proc
	runtime.GOMAXPROCS(ctx.Config.App.NumThreads)

	startLogging()

	/*
	 * Construct objects, validate the URLs
	 */
	ctx.ApplicationURL = checkURL(ctx.Config.App.ApplicationURL)
	checkURL(ctx.Config.App.ClamdURL)
	ctx.ClamInterceptor = &ClamInterceptor{
		ClamdURL:        ctx.Config.App.ClamdURL,
		VirusStatusCode: ctx.Config.App.VirusStatusCode,
		Scan:            clamavScanner,
	}

	/*
	 * Set up the HTTP server
	 */
	router := http.NewServeMux()

	router.HandleFunc("/clammit", infoHandler)
	router.HandleFunc("/clammit/scan", scanHandler)
	if ctx.Config.App.TestPages {
		fs := http.FileServer(http.Dir("testfiles"))
		router.Handle("/clammit/test/", http.StripPrefix("/clammit/test/", fs))
	}
	router.HandleFunc("/", scanForwardHandler)

	if !ctx.Config.App.DebugClam {
		log.SetOutput(ioutil.Discard) // go-clamd has irritating logging, so turn it off
	}

	if listener, err := getListener(ctx.Config.App.Listen, socketPerms); err != nil {
		ctx.Logger.Fatal("Unable to listen on: ", ctx.Config.App.Listen, ", reason: ", err)
	} else {
		ctx.Listener = listener
		beGraceful() // graceful shutdown from here on in
		ctx.Logger.Println("Listening on", ctx.Config.App.Listen)
		http.Serve(listener, router)
	}
}

/*
 * Starts logging
 */
func startLogging() {
	if ctx.Config.App.Logfile != "" {
		w, err := os.OpenFile(ctx.Config.App.Logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
		if err == nil {
			ctx.Logger = log.New(w, "", log.LstdFlags)
		} else {
			log.Fatal("Failed to open log file", ctx.Config.App.Logfile, ":", err)
		}
	} else {
		ctx.Logger = log.New(os.Stdout, "", log.LstdFlags)
		ctx.Logger.Println("No log file configured - using stdout")
	}
}

/*
 * Handles graceful shutdown. Sets ctx.ShuttingDown = true to stop any new
 * requests, then waits for active requests to complete before closing the
 * HTTP listener.
 */
func beGraceful() {
	sigchan := make(chan os.Signal)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		activity := 0
		for {
			select {
			case _ = <-sigchan:
				ctx.Logger.Println("Received termination signal")
				ctx.ShuttingDown = true
				for activity > 0 {
					ctx.Logger.Printf("There are %d active requests, waiting", activity)
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
func checkURL(urlString string) *url.URL {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		log.Fatal("Invalid URL:", urlString)
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
func getListener(address string, socketPerms int) (listener net.Listener, err error) {
	if address == "" {
		return nil, fmt.Errorf("No listen address specified")
	}
	if idx := strings.Index(address, ":"); idx >= 0 {
		scheme := address[0:idx]
		switch scheme {
		case "tcp", "tcp4":
			path := address[idx+1:]
			if strings.Index(path, ":") == -1 {
				path = ":" + path
			}
			listener, err = net.Listen(scheme, path)
		case "tcp6": // general form: [host]:port
			path := address[idx+1:]
			if strings.Index(path, "[") != 0 { // port only
				if strings.Index(path, ":") != 0 { // no leading :
					path = ":" + path
				}
			}
			listener, err = net.Listen(scheme, path)
		case "unix", "unixpacket":
			path := address[idx+1:]
			if listener, err = net.Listen(scheme, path); err == nil {
				os.Chmod(path, os.FileMode(socketPerms))
			}
		default: // assume TCP4 address
			listener, err = net.Listen("tcp", address)
		}
	} else { // no scheme, port only specified
		listener, err = net.Listen("tcp", ":"+address)
	}
	return listener, err
}

/*
 * Handler for /scan
 *
 * Virus checks file and sends response
 */
func scanHandler(w http.ResponseWriter, req *http.Request) {
	if ctx.ShuttingDown {
		return
	}
	ctx.ActivityChan <- 1
	defer func() { ctx.ActivityChan <- -1 }()

	if !ctx.ClamInterceptor.Handle(w, req, req.Body) {
		w.Write([]byte("No virus found"))
	}
}

/*
 * Handler for scan & forward
 *
 * Constructs a forwarder and calls it
 */
func scanForwardHandler(w http.ResponseWriter, req *http.Request) {
	if ctx.ShuttingDown {
		return
	}
	ctx.ActivityChan <- 1
	defer func() { ctx.ActivityChan <- -1 }()

	fw := forwarder.NewForwarder(ctx.ApplicationURL, ctx.Config.App.ContentMemoryThreshold, ctx.ClamInterceptor)
	fw.SetLogger(ctx.Logger, ctx.Config.App.Debug)
	fw.HandleRequest(w, req)
}

/*
 * Handler for /info
 *
 * Validates the Clamd connection
 * Emits the information as a JSON response
 */
func infoHandler(w http.ResponseWriter, req *http.Request) {
	if ctx.ShuttingDown {
		return
	}
	ctx.ActivityChan <- 1
	defer func() { ctx.ActivityChan <- -1 }()

	c := clamd.NewClamd(ctx.ClamInterceptor.ClamdURL)
	info := &Info{
		ClamdURL: ctx.ClamInterceptor.ClamdURL,
	}
	if err := c.Ping(); err != nil {
		// If we can't ping the Clamd server, no point in making the remaining requests
		info.PingResult = err.Error()
	} else {
		info.PingResult = "Connected to server OK"
		if response, err := c.Version(); err != nil {
			info.Version = err.Error()
		} else {
			for s := range response {
				info.Version += s
			}
		}
		/*
		 * Validate the Clamd response for a viral string
		 */
		reader := bytes.NewReader(clamd.EICAR)
		if response, err := c.ScanStream(reader); err != nil {
			info.TestScanVirusResult = err.Error()
		} else {
			for s := range response {
				info.TestScanVirusResult += s
			}
		}
		/*
		 * Validate the Clamd response for a non-viral string
		 */
		reader = bytes.NewReader([]byte("foo bar mcgrew"))
		if response, err := c.ScanStream(reader); err != nil {
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
	w.Write([]byte(s))
}
