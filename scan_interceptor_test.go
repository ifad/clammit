package main

import (
	"bytes"
	"clammit/scanner"
	"errors"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const virusCode = 418

var mockVirusFound = false
var mockScanErr error
var mockScanned []string

type MockScanner struct {
	scanner.Engine
}

func (s MockScanner) HasVirus(reader io.Reader) (bool, error) {
	data, _ := io.ReadAll(reader)
	mockScanned = append(mockScanned, string(data))
	return mockVirusFound, mockScanErr
}

var scanInterceptor = ScanInterceptor{
	VirusStatusCode: virusCode,
	Scanner:         new(MockScanner),
}

var handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { scanInterceptor.Handle(w, req, req.Body) })

func TestNonMultipartRequest_EmptyBody(t *testing.T) {
	setup()
	req := newHTTPRequest("GET", "", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != 200 {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, 200)
	}
}

func TestNonMultipartRequest_VirusFound_Without_ContentDisposition(t *testing.T) {
	setup()
	mockVirusFound = true
	req := newHTTPRequest("POST", "application/octet-stream", bytes.NewReader([]byte(`<virus/>`)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != virusCode {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, virusCode)
	}
	expected := `File untitled has a virus!`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestNonMultipartRequest_VirusFound_With_ContentDisposition(t *testing.T) {
	setup()
	mockVirusFound = true
	req := newHTTPRequest("POST", "application/octet-stream", bytes.NewReader([]byte(`<virus/>`)))
	req.Header["Content-Disposition"] = []string{"attachment;filename=virus.dat"}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != virusCode {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, virusCode)
	}
	expected := `File virus.dat has a virus!`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestNonMultipartRequest_Clean(t *testing.T) {
	setup()
	mockVirusFound = false
	req := newHTTPRequest("POST", "application/octet-stream", bytes.NewReader([]byte(`<clean/>`)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != 200 {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, 200)
	}
}

func TestMultipartRequest_VirusFound(t *testing.T) {
	setup()
	mockVirusFound = true

	body, contentType := makeMultipartBody()

	req := newHTTPRequest("POST", contentType, body)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != virusCode {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, virusCode)
	}
	expected := `File foo.dat has a virus!`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestMultipartRequest_Clean(t *testing.T) {
	setup()
	mockVirusFound = false

	body, contentType := makeMultipartBody()

	req := newHTTPRequest("POST", contentType, body)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != 200 {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, virusCode)
	}
}

func makeMultipartBody() (*bytes.Buffer, string) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	defer writer.Close()

	addPart(writer, "file1", "foo.dat")
	addPart(writer, "file2", "bar.dat")

	err := writer.Close()
	if err != nil {
		log.Fatal("Can't close multipart writer:", err)
	}

	return body, writer.FormDataContentType()
}

func addPart(w *multipart.Writer, name, fileName string) {
	part, err := w.CreateFormFile(name, fileName)
	if err != nil {
		log.Fatal("Cannot create multipart body:", err)
	}

	_, err = io.WriteString(part, name)
	if err != nil {
		log.Fatal("Can't write part to multipart body:", err)
	}
	return
}

func setup() {
	ctx = &Ctx{
		ShuttingDown: false,
	}
	ctx.Logger = log.New(os.Stdout, "", log.LstdFlags)
	ctx.Config.App.Debug = true
	mockVirusFound = false
	mockScanErr = nil
	mockScanned = nil
}

func newHTTPRequest(method string, contentType string, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, "http://clammit/scan", body)
	req.Header = map[string][]string{
		"X-Forwarded-For": []string{"kermit"},
	}
	if contentType != "" {
		req.Header["Content-Type"] = []string{contentType}
	}
	return req
}

func TestRequest_ScanErrorIsRefused(t *testing.T) {
	setup()
	mockScanErr = errors.New("clamd unavailable")
	req := newHTTPRequest("POST", "application/octet-stream", bytes.NewReader([]byte(`<data/>`)))
	rr := httptest.NewRecorder()
	if handled := scanInterceptor.Handle(rr, req, req.Body); !handled {
		t.Fatal("a scan error must stop the request from being forwarded")
	}
	if rr.Code != 500 {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, 500)
	}
}

func TestRequest_MissingContentTypeIsScanned(t *testing.T) {
	setup()
	mockVirusFound = true
	req := newHTTPRequest("POST", "", bytes.NewReader([]byte(`<virus/>`)))
	rr := httptest.NewRecorder()
	if handled := scanInterceptor.Handle(rr, req, req.Body); !handled {
		t.Fatal("a body without Content-Type must be scanned, not forwarded unscanned")
	}
	if rr.Code != virusCode {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, virusCode)
	}
	if len(mockScanned) != 1 || mockScanned[0] != `<virus/>` {
		t.Errorf("expected the raw body to be scanned once, got %q", mockScanned)
	}
}

func TestRequest_MalformedContentTypeIsScanned(t *testing.T) {
	setup()
	mockVirusFound = true
	req := newHTTPRequest("POST", "multipart/form-data; boundary", bytes.NewReader([]byte(`<virus/>`)))
	rr := httptest.NewRecorder()
	if handled := scanInterceptor.Handle(rr, req, req.Body); !handled {
		t.Fatal("a body with an unparseable Content-Type must be scanned, not forwarded unscanned")
	}
	if rr.Code != virusCode {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, virusCode)
	}
}

func TestMultipartRequest_MissingBoundaryIsRefused(t *testing.T) {
	setup()
	req := newHTTPRequest("POST", "multipart/form-data", bytes.NewReader([]byte(`<virus/>`)))
	rr := httptest.NewRecorder()
	if handled := scanInterceptor.Handle(rr, req, req.Body); !handled {
		t.Fatal("a multipart body without a boundary must not be forwarded unscanned")
	}
	if rr.Code != 400 {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, 400)
	}
}
