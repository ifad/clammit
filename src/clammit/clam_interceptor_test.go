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
var mockScan = func(ClamdURL string, reader io.Reader) (bool, error) {
	return mockVirusFound, nil
}
var clamInterceptor = ClamInterceptor{
	ClamdURL:        "unix:/dev/null",
	VirusStatusCode: virusCode,
	Scan:            mockScan,
}
var handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { clamInterceptor.Handle(w, req, req.Body) })

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
