/*
 * The task of the forwarder is to take an HTTP request, pass it to the
 * Interceptor, and then only if the Interceptor returns false, pass it
 * on to the application.
 *
 * Importantly, the forwarder will save the request body to file, as it
 * is not possible to stream the body first to the Interceptor, then to
 * the application without doing so. This adds an inevitable overhead.
 */
package forwarder

import (
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

const applicationUrlHeader string = "X-Clammit-Backend"

/*
 * The Interceptor will be passed the request to examine and pass.
 *
 * If the Interceptor deems that the request should not be forwarded to the
 * target application, it should return true.
 *
 * The request body is at EOF, so if the Interceptor needs to examine the
 * body, it should work with the "body" parameter.
 *
 * Also, the Interceptor is passed the ResponseWriter. If it fails the
 * request, the Interceptor must set the response status code and body
 * as it deems appropriate - the Forwarder will not do this.
 */
type Interceptor interface {
	Handle(w http.ResponseWriter, req *http.Request, body io.Reader) bool
}

/*
 * Forwarder implementation
 */
type Forwarder struct {
	applicationURL         *url.URL
	interceptor            Interceptor
	logger                 *log.Logger
	debug                  bool
	contentMemoryThreshold int64
}

/*
 * Constructs a new forwarder. Pass in the application URL and the interceptor.
 */
func NewForwarder(applicationURL *url.URL, contentMemoryThreshold int64, interceptor Interceptor) *Forwarder {
	return &Forwarder{
		applicationURL:         applicationURL,
		interceptor:            interceptor,
		logger:                 log.New(ioutil.Discard, "", 0),
		contentMemoryThreshold: contentMemoryThreshold,
	}
}

/*
 * Sets the logger. The default is to log nothing, so if you wish for forwarder
 * debug information, you will need to call this method.
 */
func (f *Forwarder) SetLogger(logger *log.Logger, debug bool) {
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}
	f.logger = logger
	f.debug = debug
}

/*
 * Handles the given HTTP request.
 */
func (f *Forwarder) HandleRequest(w http.ResponseWriter, req *http.Request) {
	// Catch panics and return a 500 Internal Server Error
	defer func() {
		if err := recover(); err != nil {
			f.logger.Printf("ERROR %s", err)

			// Return 500 response
			http.Error(w, "Internal Server Error", 500)
		}
	}()

	if f.debug {
		f.logger.Println("Received scan request")
	}

	//
	// Save the request body
	//
	bodyHolder, err := NewBodyHolder(req.Body, req.ContentLength, f.contentMemoryThreshold)
	if err != nil {
		f.logger.Println("Unable to save body to local store: %s", err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}
	defer bodyHolder.Close()

	//
	// Allow the interceptor its chance
	//
	if f.interceptor != nil {
		if f.debug {
			f.logger.Println("Passing to interceptor")
		}
		r, _ := bodyHolder.GetReadCloser()
		defer r.Close()
		if f.interceptor.Handle(w, req, r) {
			f.logger.Println("Interceptor has deemed that this request should not be forwarded")
			return
		}
	}

	if f.debug {
		f.logger.Println("Interceptor passed this request")
	}

	//
	// Forward the request to the configured server
	//
	body, _ := bodyHolder.GetReadCloser()
	defer body.Close()
	resp, err := f.forwardRequest(req, body, bodyHolder.ContentLength())
	if err != nil {
		f.logger.Printf("Failed to forward request: %s", err.Error())
		http.Error(w, "Bad Gateway", 502)
		return
	}
	if resp == nil {
		f.logger.Printf("Failed to forward request: no response at all")
		http.Error(w, "Bad Gateway", 502)
		return
	}
	if resp.Body != nil {
		f.logger.Printf("Request forwarded, response %s\n", resp.Status)
		defer resp.Body.Close()
	}

	//
	// and return the response
	//
	for key, val := range resp.Header {
		w.Header()[key] = val
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		io.Copy(w, resp.Body) // this could throw an error, but there's nowt we can do about it now
	}

	return
}

/*
 * Forwards the request to the application. This function tries to preserve as much
 * as possible of the request - headers and body.
 */
func (f *Forwarder) forwardRequest(req *http.Request, body io.Reader, contentLength int64) (*http.Response, error) {
	client, url := f.getClient(req)
	freq, _ := http.NewRequest(req.Method, url.String(), body)
	freq.ContentLength = contentLength
	for key, val := range req.Header {
		freq.Header[key] = val
	}

	// Be nice and add client IP to forwarding chain
	if req.RemoteAddr != "@" {
		xff := freq.Header.Get("X-Forwarded-For")
		if xff != "" {
			xff += ", "
		}
		xff += strings.Split(req.RemoteAddr, ":")[0]
		freq.Header.Set("X-Forwarded-For", xff)
	}

	return client.Do(freq)
}

func (f *Forwarder) getApplicationURL(req *http.Request) *url.URL {
	// Return the applicationURL if it's set
	if f.applicationURL != nil && f.applicationURL.String() != "" {
		return f.applicationURL
	}

	// Otherwise check for the X-Clammit-Backend header
	url, err := url.Parse(req.Header.Get(applicationUrlHeader))
	if err != nil {
		f.logger.Panicf("Error parsing application URL in %s: %s (%s)", applicationUrlHeader, err.Error(), req.Header.Get(applicationUrlHeader))
		return nil
	}

	if len(url.String()) == 0 {
		f.logger.Panicf("No application URL available - header %s is blank", applicationUrlHeader)
	}

	return url
}

/*
 * Gets an appropriate net/http.Client. I'm not sure if this is necessary, but it forces the issue.
 */
func (f *Forwarder) getClient(req *http.Request) (*http.Client, *url.URL) {
	applicationURL := f.getApplicationURL(req)
	url := &url.URL{
		Scheme:   applicationURL.Scheme,
		Opaque:   applicationURL.Opaque,
		User:     applicationURL.User, // TODO: clone this
		Host:     applicationURL.Host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
		Fragment: req.URL.Fragment,
	}
	if applicationURL.Scheme == "unix" {
		f.logger.Printf("Forwarding to unix socket %s", applicationURL.Path)
		url.Scheme = "http"
		url.Host = "x"
		jar, _ := cookiejar.New(nil)
		return &http.Client{
			Jar: jar,
			Transport: &http.Transport{
				Dial: func(network, addr string) (net.Conn, error) {
					return net.Dial("unix", applicationURL.Path)
				},
			},
		}, url
	} else {
		f.logger.Printf("Forwarding to %s", applicationURL.String())
		return &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}, url
	}
}
