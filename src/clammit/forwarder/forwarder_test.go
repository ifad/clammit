package forwarder

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testResponseWriter struct {
	Headers    http.Header
	StatusCode int
	Body       *bytes.Buffer
}

func emptyBody() io.Reader {
	return bytes.NewReader([]byte{})
}

func NewTestResponseWriter() *testResponseWriter {
	return &testResponseWriter{
		Headers:    make(http.Header),
		StatusCode: -1,
		Body:       &bytes.Buffer{},
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

type testInterceptor func(http.ResponseWriter, *http.Request, io.Reader) bool

func (i testInterceptor) Handle(w http.ResponseWriter, req *http.Request, body io.Reader) bool {
	return i(w, req, body)
}

func TestInterceptor(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Request was forwarded but should not have been")
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)

	bodyText := "This is the request body"

	fw := NewForwarder(tsURL, 10000, testInterceptor(func(w http.ResponseWriter, req *http.Request, body io.Reader) bool {
		buf := make([]byte, 10000)
		if n, err := body.Read(buf); err != nil && err != io.EOF {
			t.Fatalf("Got error reading body: %s", err.Error())
		} else if string(buf[0:n]) != bodyText {
			t.Fatalf("Read body failed: X%vX, expected X%vX", string(buf[0:n]), bodyText)
		}
		w.Header().Set("foo", "bar")
		w.WriteHeader(204)
		w.Write([]byte("This is a response"))
		return true
	}))

	req, _ := http.NewRequest("POST", "http://localhost:9999/bar?crazy=true", strings.NewReader(bodyText))
	w := NewTestResponseWriter()

	fw.HandleRequest(w, req)

	if w.StatusCode != 204 {
		t.Fatalf("Response: StatusCode was %d, expected %d", w.StatusCode, 204)
	}
	if w.Header().Get("Foo") != "bar" {
		t.Fatalf("Response: Header['foo'] not set")
	}
	if w.Body.String() != "This is a response" {
		t.Fatalf("Response: Body is: %s", w.Body.String())
	}
}

func TestForwarding(t *testing.T) {
	requestText := "This is a request"
	responseText := "This is the response"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bar" {
			t.Fatalf("Request path incorrect: %s, expected %s", r.URL.Path, "bar")
		}
		if r.URL.RawQuery != "crazy=true" {
			t.Fatalf("Request raw query incorrect: %s, expected %s", r.URL.RawQuery, "crazy=true")
		}
		if r.Header.Get("myheader") != "headervalue" {
			t.Fatalf("Request header 'myheader' is not set")
		}
		if r.Header.Get("X-Forwarded-For") != "foobar" {
			t.Fatalf("Request header 'X-Forwarded-For' is not set")
		}
		if r.Body == nil {
			t.Fatal("Forwarded request has no body")
		}
		defer r.Body.Close()
		if body, err := ioutil.ReadAll(r.Body); err != nil {
			t.Fatal("Unexpected error reading request body:", err)
		} else if string(body) != requestText {
			t.Fatalf("Request body is %s, expected %s", string(body), requestText)
		}
		w.Header().Add("foo", "bar")
		w.WriteHeader(202)
		w.Write([]byte(responseText))
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)

	fw := NewForwarder(tsURL, 10000, nil)

	req, _ := http.NewRequest("POST", "http://localhost:99999/bar?crazy=true", strings.NewReader(requestText))
	req.Header.Set("myheader", "headervalue")
	req.RemoteAddr = "foobar:1234"
	w := NewTestResponseWriter()

	fw.HandleRequest(w, req)

	if w.StatusCode != 202 {
		t.Fatalf("Response: StatusCode was %d, expected %d", w.StatusCode, 202)
	}
	if w.Header().Get("Foo") == "" {
		t.Fatalf("Response: Header['foo'] not set: %v", w.Headers)
	}
	if w.Body.String() != responseText {
		t.Fatalf("Response: Body is: %s", w.Body.String())
	}
}

func TestHostForwarding(t *testing.T) {
	requestText := "This is a request"
	responseText := "This is the response"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostname := strings.Split(r.Host, ":")[0]
		if hostname != "localhost" {
			t.Fatalf("Host field incorrect: %v, expected %v", hostname, "localhost")
		}
		defer r.Body.Close()
		w.WriteHeader(202)
		w.Write([]byte(responseText))
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)

	fw := NewForwarder(tsURL, 10000, nil)

	req, _ := http.NewRequest("POST", "http://localhost:99999/bar?crazy=true", strings.NewReader(requestText))
	req.Header.Set("myheader", "headervalue")
	req.RemoteAddr = "foobar:1234"
	w := NewTestResponseWriter()

	fw.HandleRequest(w, req)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostname := strings.Split(r.Host, ":")[0]
		if hostname != "testhost" {
			t.Fatalf("Host field incorrect: %v, expected %v", hostname, "testhost")
		}
		defer r.Body.Close()
		w.WriteHeader(202)
		w.Write([]byte(responseText))
	}))
	defer ts.Close()
	tsURL, _ = url.Parse(ts.URL)

	fw = NewForwarder(tsURL, 10000, nil)

	req, _ = http.NewRequest("POST", "http://localhost:99999/bar?crazy=true", strings.NewReader(requestText))
	req.Host = "testhost"
	req.Header.Set("myheader", "headervalue")
	req.RemoteAddr = "foobar:1234"
	w = NewTestResponseWriter()

	fw.HandleRequest(w, req)
}

func TestMultiForwarder(t *testing.T) {
	requestText := "This is a request"

	fw := NewForwarder(nil, 10000, nil)

	// Build two backends
	backend1ResponseText := "backend1"
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
		w.Write([]byte(backend1ResponseText))
	}))
	defer backend1.Close()
	backend1URL, _ := url.Parse(backend1.URL)

	backend2ResponseText := "backend2"
	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
		w.Write([]byte(backend2ResponseText))
	}))
	defer backend2.Close()
	backend2URL, _ := url.Parse(backend2.URL)

	// Ensure they have different urls
	assert.NotEqual(t, backend1URL, backend2URL)

	// Test a request for backend1
	req1, _ := http.NewRequest("POST", "http://localhost:99999/bar", strings.NewReader(requestText))
	req1.Header.Set("X-Clammit-Backend", backend1URL.String())
	w1 := NewTestResponseWriter()

	fw.HandleRequest(w1, req1)

	assert.Equal(t, w1.StatusCode, 202)
	assert.Equal(t, w1.Body.String(), backend1ResponseText)

	// Test a request for backend2
	req2, _ := http.NewRequest("POST", "http://localhost:99999/bar", strings.NewReader(requestText))
	req2.Header.Set("X-Clammit-Backend", backend2URL.String())
	w2 := NewTestResponseWriter()

	fw.HandleRequest(w2, req2)

	assert.Equal(t, w2.StatusCode, 202)
	assert.Equal(t, w2.Body.String(), backend2ResponseText)

	// Test a request without the backend header
	req3, _ := http.NewRequest("POST", "http://localhost:99999/bar", strings.NewReader(requestText))
	w3 := NewTestResponseWriter()

	fw.HandleRequest(w3, req3)

	assert.Equal(t, w3.StatusCode, 500)
	assert.Equal(t, w3.Body.String(), "Internal Server Error\n")
}

func TestForwardingWithRedirectPOST(t *testing.T) {
	requestText := "This is a request"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Header().Add("Location", "https://localhost:12345/foobar")
		w.WriteHeader(302)
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)

	fw := NewForwarder(tsURL, 10000, nil)

	req, _ := http.NewRequest("POST", "http://localhost:99999/bar?crazy=true", strings.NewReader(requestText))

	w := NewTestResponseWriter()

	fw.HandleRequest(w, req)

	require.Equal(t, 302, w.StatusCode)
	assert.Equal(t, "https://localhost:12345/foobar", w.Header().Get("Location"))
}

func TestForwardingWithRedirectGET(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Header().Add("Location", "https://localhost:12345/foobar")
		w.WriteHeader(302)
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)

	fw := NewForwarder(tsURL, 10000, nil)

	req, _ := http.NewRequest("GET", "http://localhost:99999/bar?crazy=true", emptyBody())
	req.Header.Set("X-Clammit-Backend", tsURL.String())

	w := NewTestResponseWriter()

	fw.HandleRequest(w, req)

	require.Equal(t, 302, w.StatusCode)
	assert.Equal(t, "https://localhost:12345/foobar", w.Header().Get("Location"))
}
