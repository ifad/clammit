package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const virusCode = 418

var mockVirusFound = false

type MockScanner struct {
}

func (s MockScanner) hasVirus(reader io.Reader) (bool, error) {
	return mockVirusFound, nil
}

func (s MockScanner) scan(reader io.Reader) (chan string, error) {
	return nil, nil
}

func (s MockScanner) ping() error {
	return nil
}

func (s MockScanner) version() (chan string, error) {
	return nil, nil
}

var scanInterceptor = ScanInterceptor{
	VirusStatusCode: virusCode,
	Scanner:         &MockScanner{},
}

var handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { scanInterceptor.Handle(w, req, req.Body) })

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

func setup() {
	ctx = &Ctx{
		ShuttingDown: false,
	}
	ctx.Logger = log.New(os.Stdout, "", log.LstdFlags)
}

func newHTTPRequest(method string, contentType string, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, "http://clammit/scan", body)
	req.Header = map[string][]string{
		"Content-Type":    []string{contentType},
		"X-Forwarded-For": []string{"kermit"},
	}
	return req
}
