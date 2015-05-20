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
	"clammit/scratch"
	"net/http"
	"net/url"
	"log"
	"io"
	"os"
	"io/ioutil"
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
}

/*
 * Constructs a new forwarder. Pass in the application URL and the interceptor.
 */
func NewForwarder( applicationURL *url.URL, interceptor Interceptor ) *Forwarder {
	return &Forwarder{
		applicationURL: applicationURL,
		interceptor: interceptor,
		logger: log.New(ioutil.Discard, "", 0),
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
	sa, err := scratch.NewScratchArea("","clammit")
	if err != nil {
		f.logger.Println( "Unable to create scratch directory: %s", err.Error() )
		w.WriteHeader( 503 )
		w.Write( []byte("Clammit is unable to create scratch directory") )
		return
	}
	defer sa.Cleanup()
	bodyFile, err := sa.NewFile("body")
	if err != nil {
		f.logger.Println( "Failed to create scratch file: %s", err.Error() )
		w.WriteHeader( 500 )
		w.Write( []byte("Clammit is unable to begin saving the request") )
		return
	}
	var contentLength int64
	if req.Body != nil {
		defer req.Body.Close()
		count, err := io.Copy( bodyFile, req.Body )
		if err != nil {
			f.logger.Println( "Failed to save body to scratch file: %s", err.Error() )
			w.WriteHeader( 500 )
			w.Write( []byte("Clammit is unable to save the request") )
			return
		}
		contentLength = count
	}
	bodyFile.Close()

	//
	// Allow the interceptor its chance
	//
	if f.interceptor != nil {
		f.logger.Println( "Passing to interceptor" )
		r, _ := os.Open( bodyFile.Name() )
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

	resp, err := f.forwardRequest( req, bodyFile.Name(), contentLength )
//	if err != nil {
//		f.logger.Printf( "Failed to forward request: %s", err.Error() )
//		w.WriteHeader( 500 )
//		w.Write( []byte("Clammit is unable to forward the request") )
//		return
//	}
	defer resp.Body.Close()

	//
	// and return the response
	//
	for key, val := range resp.Header {
		w.Header()[key] = val
	}
	w.WriteHeader( resp.StatusCode )
	io.Copy( w, resp.Body ) // this could throw an error, but there's nowt we can do about it now

	return
}

/*
 * Forwards the request to the application. This function tries to preserve as much
 * as possible of the request - headers and body.
 */
func (f *Forwarder) forwardRequest( req *http.Request, bodyFile string, contentLength int64 ) (*http.Response,error) {
	newBody, err := os.Open(bodyFile)
	if err != nil {
		return nil, err
	}
	url := &url.URL{
		Scheme:   f.applicationURL.Scheme,
		Opaque:   f.applicationURL.Opaque,
		User:     f.applicationURL.User, // TODO: clone this
		Host:     f.applicationURL.Host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
		Fragment: req.URL.Fragment,
	}
	client := &http.Client{}
	f.logger.Printf( "Will forward to: %s", url.String() )
	freq, err := http.NewRequest( req.Method, url.String(), newBody )
	freq.ContentLength = contentLength
	for key, val := range req.Header {
		freq.Header[key] = val
	}
	return client.Do(freq)
}
