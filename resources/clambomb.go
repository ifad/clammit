/*
 * This is a utility program to fire (synchronously) a whole load of
 * form POSTs at clammit.
 */
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

var virus bool
var count int
var requestUrl string
var fileParameter string
var filename string

func init() {
	flag.IntVar(&count, "count", 1, "Number of requests to send")
	flag.StringVar(&requestUrl, "url", "http://localhost:8438/foo", "URL to post to")
	flag.StringVar(&fileParameter, "param", "qqfile", "File parameter name")
	flag.StringVar(&filename, "filename", "clean.dat", "File to send")
}

func main() {
	flag.Parse()

	errorCount := 0
	params := map[string]string{}

	for i := 0; i < count; i++ {
		fmt.Println("Send request:", i)
		req, err := newFileUploadRequest(requestUrl, params, fileParameter, filename)
		if err != nil {
			fmt.Println("Could not create upload request:", err)
			os.Exit(1)
		}
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			errorCount++
		} else {
			if resp.StatusCode > 299 {
				errorCount++
			}
			resp.Body.Close()
		}
	}

	fmt.Println("Error count:  ", errorCount)
	fmt.Println("Success count:", count-errorCount)
}

func newFileUploadRequest(uri string, params map[string]string, paramName, path string) (*http.Request, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(paramName, filepath.Base(path))
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(part, file)

	for key, val := range params {
		_ = writer.WriteField(key, val)
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", uri, body)
	if err == nil {
		req.Header.Set("Content-Type", writer.FormDataContentType())
	}
	return req, err
}
