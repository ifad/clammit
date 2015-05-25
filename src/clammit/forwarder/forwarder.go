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
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"log"
	"io"
	"io/ioutil"
	"strings"
)

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
	Handle( w http.ResponseWriter, req *http.Request, body io.Reader ) bool
}

/*
 * Forwarder implementation
 */
type Forwarder struct {
	applicationURL *url.URL
	interceptor Interceptor
	logger *log.Logger
	contentMemoryThreshold int64
}

/*
 * Constructs a new forwarder. Pass in the application URL and the interceptor.
 */
func NewForwarder( applicationURL *url.URL, contentMemoryThreshold int64, interceptor Interceptor ) *Forwarder {
	return &Forwarder{
		applicationURL: applicationURL,
		interceptor: interceptor,
		logger: log.New(ioutil.Discard, "", 0),
		contentMemoryThreshold: contentMemoryThreshold,
	 }
}

/*
 * Sets the logger. The default is to log nothing, so if you wish for forwarder
 * debug information, you will need to call this method.
 */
func (f *Forwarder) SetLogger( logger *log.Logger ) {
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}
	f.logger = logger
}

/*
 * Handles the given HTTP request.
 */
func (f *Forwarder) HandleRequest( w http.ResponseWriter, req *http.Request ) {
	f.logger.Println( "Received scan request" )

	//
	// Save the request body
	//
	bodyHolder, err := NewBodyHolder( req.Body, req.ContentLength, f.contentMemoryThreshold )
	if err != nil {
		f.logger.Println( "Unable to save body to local store: %s", err.Error() )
		w.WriteHeader( 503 )
		w.Write( []byte("Clammit is unable to save body to local store") )
		return
	}
	defer bodyHolder.Close()

	//
	// Allow the interceptor its chance
	//
	if f.interceptor != nil {
		f.logger.Println( "Passing to interceptor" )
		r, _ := bodyHolder.GetReadCloser()
		defer r.Close()
		if( f.interceptor.Handle( w, req, r ) ) {
			f.logger.Println( "Interceptor has deemed that this request should not be forwarded" )
			return
		}
	}
	f.logger.Println( "Interceptor passed this request" )

	//
	// Forward the request to the configured server
	//
	body, _ := bodyHolder.GetReadCloser()
	defer body.Close()
	resp, _ := f.forwardRequest( req, body, bodyHolder.ContentLength() )
	if err != nil {
		f.logger.Printf( "Failed to forward request: %s", err.Error() )
		w.WriteHeader( 500 )
		w.Write( []byte("Clammit is unable to forward the request") )
		return
	}
	if resp == nil {
		f.logger.Printf( "Failed to forward request: no response at all" )
		w.WriteHeader( 500 )
		w.Write( []byte("Clammit is unable to forward the request") )
		return
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	//
	// and return the response
	//
	for key, val := range resp.Header {
		w.Header()[key] = val
	}
	w.WriteHeader( resp.StatusCode )
	if( resp.Body != nil ) {
		io.Copy( w, resp.Body ) // this could throw an error, but there's nowt we can do about it now
	}

	return
}

/*
 * Forwards the request to the application. This function tries to preserve as much
 * as possible of the request - headers and body.
 */
func (f *Forwarder) forwardRequest( req *http.Request, body io.Reader, contentLength int64 ) (*http.Response,error) {
	client, url := f.getClient( req )
	freq, _ := http.NewRequest( req.Method, url.String(), body )
	freq.ContentLength = contentLength
	for key, val := range req.Header {
		freq.Header[key] = val
	}

	// Be nice and add client IP to forwarding chain
	if req.RemoteAddr != "@" {
		xff := freq.Header.Get( "X-Forwarded-For" )
		if xff != "" {
			xff += ", "
		}
		xff += req.Header.Get( "X-Forwarded-For" ) + strings.Split(req.RemoteAddr, ":")[0]
		freq.Header.Set( "X-Forwarded-For", xff )
	}

	return client.Do(freq)
}

/*
 * Gets an appropriate net/http.Client. I'm not sure if this is necessary, but it forces the issue.
 */
func (f *Forwarder) getClient( req *http.Request) (*http.Client, *url.URL) {
	url := &url.URL{
		Scheme:   f.applicationURL.Scheme,
		Opaque:   f.applicationURL.Opaque,
		User:     f.applicationURL.User, // TODO: clone this
		Host:     f.applicationURL.Host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
		Fragment: req.URL.Fragment,
	}
	if f.applicationURL.Scheme == "unix" {
		f.logger.Printf( "Will forward to: %s on unix socket %s", req.URL.Path, f.applicationURL.Path )
		url.Scheme = "http"
		url.Host = "x"
		jar, _ := cookiejar.New(nil)
		return &http.Client{
			Jar: jar,
			Transport: &http.Transport{
				Dial: func(network, addr string)(net.Conn, error) {
					return net.Dial("unix", f.applicationURL.Path)
				},
			},
		}, url
	} else {
		f.logger.Printf( "Will forward to: %s at %s", req.URL.Path, f.applicationURL.String() )
		return &http.Client{}, url
	}
}
