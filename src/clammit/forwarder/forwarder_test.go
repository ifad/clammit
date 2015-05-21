package forwarder

import (
	"testing"
	"net/url"
	"net/http"
	"net/http/httptest"
	"bytes"
	"io"
	"io/ioutil"
	"strings"
)

type testResponseWriter struct {
	Headers http.Header
	StatusCode int
	Body *bytes.Buffer
}
func NewTestResponseWriter() *testResponseWriter {
	return &testResponseWriter{
		Headers: make(http.Header),
		StatusCode: -1,
		Body: &bytes.Buffer{},
	}
}
func (w *testResponseWriter) Header() http.Header {
	return w.Headers
}
func (w *testResponseWriter) Write(body []byte) (int, error) {
	return w.Body.Write(body)
}
func (w *testResponseWriter) WriteHeader(statusCode int) {
	w.StatusCode = statusCode
}

type testInterceptor func( http.ResponseWriter, *http.Request, io.Reader )bool
func (i testInterceptor) Handle( w http.ResponseWriter, req *http.Request, body io.Reader ) bool {
	return i(w,req,body)
}

func TestInterceptor( t *testing.T ) {
	ts := httptest.NewServer( http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal( "Request was forwarded but should not have been" )
	}) )
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)

	bodyText := "This is the request body"

	fw := NewForwarder( tsURL, testInterceptor( func( w http.ResponseWriter, req *http.Request, body io.Reader ) bool {
		buf := make([]byte,10000)
		if n, err := body.Read(buf); err != nil && err != io.EOF {
			t.Fatalf( "Got error reading body: %s", err.Error() )
		} else if string(buf[0:n]) != bodyText {
			t.Fatalf( "Read body failed: X%vX, expected X%vX %v", string(buf[0:n]), bodyText )
		}
		w.Header().Set("foo","bar")
		w.WriteHeader( 204 )
		w.Write( []byte( "This is a response" ) )
		return true
	}) )

	req, _ := http.NewRequest( "POST","http://localhost:9999/bar?crazy=true", strings.NewReader(bodyText) )
	w := NewTestResponseWriter()

	fw.HandleRequest( w, req, true )

	if w.StatusCode != 204 {
		t.Fatalf( "Response: StatusCode was %d, expected %d", w.StatusCode, 204 )
	}
	if w.Header().Get("Foo") != "bar" {
		t.Fatalf( "Response: Header['foo'] not set" )
	}
	if w.Body.String() != "This is a response" {
		t.Fatalf( "Response: Body is: %s", w.Body.String() )
	}
}

func TestForwarding( t *testing.T ) {
	requestText := "This is a request"
	responseText := "This is the response"

	ts := httptest.NewServer( http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bar" {
			t.Fatalf( "Request path incorrect: %s, expected %s", r.URL.Path, "bar" )
		}
		if r.URL.RawQuery != "crazy=true" {
			t.Fatalf( "Request raw query incorrect: %s, expected %s", r.URL.RawQuery, "crazy=true" )
		}
		if r.Header.Get( "myheader" ) != "headervalue" {
			t.Fatalf( "Request header 'myheader' is not set" )
		}
		if r.Header.Get( "X-Forwarded-For" ) != "foobar" {
			t.Fatalf( "Request header 'X-Forwarded-For' is not set" )
		}
		if r.Body == nil {
			t.Fatal( "Forwarded request has no body")
		}
		defer r.Body.Close()
		if body, err := ioutil.ReadAll(r.Body); err != nil {
			t.Fatal( "Unexpected error reading request body:", err )
		} else if string(body) != requestText {
			t.Fatal( "Request body is %s, expected %s", string(body), requestText )
		}
		w.Header().Add( "foo", "bar" )
		w.WriteHeader( 202 )
		w.Write( []byte(responseText) )
	}) )
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)

	fw := NewForwarder( tsURL, nil )

	req, _ := http.NewRequest( "POST","http://localhost:99999/bar?crazy=true", strings.NewReader(requestText) )
	req.Header.Set( "myheader", "headervalue" )
	req.RemoteAddr = "foobar:1234"
	w := NewTestResponseWriter()

	fw.HandleRequest( w, req, true )

	if w.StatusCode != 202 {
		t.Fatalf( "Response: StatusCode was %d, expected %d", w.StatusCode, 202 )
	}
	if w.Header().Get("Foo") == "" {
		t.Fatalf( "Response: Header['foo'] not set: %v", w.Headers )
	}
	if w.Body.String() != responseText {
		t.Fatalf( "Response: Body is: %s", w.Body.String() )
	}
}
