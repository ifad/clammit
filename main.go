/*
 * The Clammit application intercepts HTTP POST/PATCH/PUT requests, forwards any
 * "file" form-data elements to ClamAV and only forwards the request to the
 * application if ClamAV passes all of these elements as virus-free.
 */
package main

import (
	"bytes"
	"clammit/forwarder"
	"clammit/scanner"
	"encoding/json"
	"flag"
	"fmt"
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

	"gopkg.in/gcfg.v1"
)

/* This is for Go Releaser.
 * https://github.com/goreleaser/goreleaser#a-note-about-mainversion
 */
var version = "master"

// Configuration structure, designed for gcfg
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
	// Number of CPU threads to use
	NumThreads int `gcfg:"num-threads"`
}

// Default configuration
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
	NumThreads:             runtime.NumCPU(),
}

// Application context
type Ctx struct {
	Config          Config
	ApplicationURL  *url.URL
	ScanInterceptor *ScanInterceptor
	Scanner         scanner.Scanner
	Logger          *log.Logger
	Listener        net.Listener
	ActivityChan    chan int
	ShuttingDown    bool
}

// JSON server information response
type Info struct {
	Version             string `json:"clammit_version"`
	Address             string `json:"scan_server_url"`
	PingResult          string `json:"ping_result"`
	ScannerVersion      string `json:"scan_server_version"`
	TestScanVirusResult string `json:"test_scan_virus"`
	TestScanCleanResult string `json:"test_scan_clean"`
}

// Global variables and config
var ctx *Ctx
var configFile string
var EICAR = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

func init() {
	flag.StringVar(&configFile, "config", "", "Configuration file")
}

func main() {
	/*
	 * Construct configuration, set up logging
	 */
	constructConfig()

	// Socket perms are octal!
	socketPerms := 0777
	if ctx.Config.App.SocketPerms != "" {
		if sp, err := strconv.ParseInt(ctx.Config.App.SocketPerms, 8, 0); err == nil {
			socketPerms = int(sp)
		} else {
			log.Fatalf("SocketPerms invalid (expected 4-digit octal: %s", err.Error())
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

	ctx.Scanner = new(scanner.Clamav)
	ctx.Scanner.SetLogger(ctx.Logger, ctx.Config.App.Debug)
	ctx.Scanner.SetAddress(ctx.Config.App.ClamdURL)

	ctx.ScanInterceptor = &ScanInterceptor{
		VirusStatusCode: ctx.Config.App.VirusStatusCode,
		Scanner:         ctx.Scanner,
	}

	/*
	 * Set up the HTTP server
	 */
	router := http.NewServeMux()

	router.HandleFunc("/clammit", infoHandler)
	router.HandleFunc("/clammit/scan", scanHandler)
	router.HandleFunc("/clammit/readyz", readyzHandler)

	if ctx.Config.App.TestPages {
		fs := http.FileServer(http.Dir("testfiles"))
		router.Handle("/clammit/test/", http.StripPrefix("/clammit/test/", fs))
	}
	router.HandleFunc("/", scanForwardHandler)

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
 * Returns the value of an environment variable, or a default value
 */
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

/*
 * Returns the value of an environment variable casted as int, or a default value
 */
func getIntEnv(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return fallback
}

/*
 * Returns the value of an environment variable casted as int64, or a default value
 */
func getInt64Env(key string, fallback int64) int64 {
	if value, ok := os.LookupEnv(key); ok {
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i
		}
	}
	return fallback
}

/*
 * Returns the value of an environment variable casted as boolean, or a default value
 */
func getBoolEnv(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return fallback
}

/*
 * Sets the configuration from the file and environment variables
 */
func constructConfig() {
	flag.Parse()
	ctx = &Ctx{
		ActivityChan: make(chan int),
		ShuttingDown: false,
	}

	ctx.Config.App = DefaultApplicationConfig

	// Read the configuration file if configfile is set
	if configFile != "" {
		if err := gcfg.ReadFileInto(&ctx.Config, configFile); err != nil {
			log.Fatalf("Configuration read failure: %s", err.Error())
		}
	}

	// Check for environmant variables to overwrite config
	ctx.Config.App.Listen = getEnv("CLAMMIT_LISTEN", ctx.Config.App.Listen)
	ctx.Config.App.SocketPerms = getEnv("CLAMMIT_SOCKET_PERMS", ctx.Config.App.SocketPerms)
	ctx.Config.App.ApplicationURL = getEnv("CLAMMIT_APPLICATION_URL", ctx.Config.App.ApplicationURL)
	ctx.Config.App.ClamdURL = getEnv("CLAMMIT_CLAMD_URL", ctx.Config.App.ClamdURL)
	ctx.Config.App.VirusStatusCode = getIntEnv("CLAMMIT_VIRUS_STATUS_CODE", ctx.Config.App.VirusStatusCode)
	ctx.Config.App.ContentMemoryThreshold = getInt64Env("CLAMMIT_CONTENT_MEMORY_THRESHOLD", ctx.Config.App.ContentMemoryThreshold)
	ctx.Config.App.Logfile = getEnv("CLAMMIT_LOGFILE", ctx.Config.App.Logfile)
	ctx.Config.App.TestPages = getBoolEnv("CLAMMIT_TEST_PAGES", ctx.Config.App.TestPages)
	ctx.Config.App.Debug = getBoolEnv("CLAMMIT_DEBUG", ctx.Config.App.Debug)
	ctx.Config.App.NumThreads = getIntEnv("CLAMMIT_NUM_THREADS", ctx.Config.App.NumThreads)
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

	if !ctx.ScanInterceptor.Handle(w, req, req.Body) {
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

	fw := forwarder.NewForwarder(ctx.ApplicationURL, ctx.Config.App.ContentMemoryThreshold, ctx.ScanInterceptor)
	fw.SetLogger(ctx.Logger, ctx.Config.App.Debug)
	fw.HandleRequest(w, req)
}

/*
 * Handler for /info
 *
 * Validates the Scanner connection
 * Emits the information as a JSON response
 */
func infoHandler(w http.ResponseWriter, req *http.Request) {
	if ctx.ShuttingDown {
		return
	}
	ctx.ActivityChan <- 1
	defer func() { ctx.ActivityChan <- -1 }()

	info := &Info{
		Address: ctx.Scanner.Address(),
		Version: version,
	}
	if err := ctx.Scanner.Ping(); err != nil {
		info.PingResult = err.Error()
	} else {
		info.PingResult = "Connected to server OK"
		if response, err := ctx.Scanner.Version(); err != nil {
			info.ScannerVersion = err.Error()
		} else {
			info.ScannerVersion = response
		}
		/*
		 * Validate the Clamd response for a viral string
		 */
		reader := bytes.NewReader(EICAR)
		if result, err := ctx.Scanner.Scan(reader); err != nil {
			info.TestScanVirusResult = err.Error()
		} else {
			info.TestScanVirusResult = result.String()
		}
		/*
		 * Validate the Clamd response for a non-viral string
		 */
		reader = bytes.NewReader([]byte("foo bar mcgrew"))
		if result, err := ctx.Scanner.Scan(reader); err != nil {
			info.TestScanCleanResult = err.Error()
		} else {
			info.TestScanCleanResult = result.String()
		}
	}
	// Aaaand return
	s, _ := json.Marshal(info)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(s))
}

/*
 * Handler for /clammit/readyz
 *
 * Returns 200 OK unless we are shutting down. Used in k8s.
 * See https://github.com/ifad/clammit/issues/23
 */
func readyzHandler(w http.ResponseWriter, req *http.Request) {
	if ctx.ShuttingDown {
		w.WriteHeader(503)
	} else {
		w.WriteHeader(200)
	}
}
