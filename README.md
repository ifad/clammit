# Clammit

[![Build Status](https://travis-ci.org/ifad/clammit.svg)](https://travis-ci.org/ifad/clammit)
[![Code Climate](https://codeclimate.com/github/ifad/clammit/badges/gpa.svg)](https://codeclimate.com/github/ifad/clammit)

Clammit is an HTTP interface to the ClamAV virus scanner, able to unwrap HTTP
bodies, checking them against clamd and returning a binary clean/virus status.

## Usage

Clammit parses and processes inbound HTTP requests. When it handles a request whose
Content-Length is non-zero, it will attempt to decode multipart file uploads and pass
each part or the whole body to ClamAV. If ClamAV detects a virus, clammit will then
return a response with code 418 to the caller. Otherwise, it will continue processing.

Clammit can be be used in two ways: as an intercepting proxy or as a virus check service.

### Usage as a proxy

When used as a proxy, clammit sits in between the client and your application, thus
preventing uploads with virus files to reach your application, by returning a 418 to
your app's client. For this mode to work, clammit must be able to contact your app
directly, so it is best suited when clammit is executing on the same machine as your
app.

As an example, say you have a `foo` Rails application that is configured in Nginx
like this:

```nginx
server {
  listen 80;
  server_name foobar.example.com;

  root /home/foobar/public;
  try_files $uri/index.html $uri @foobar;

  location @foobar {
    access_log /var/log/nginx/foobar.app-access.log;
    error_log  /var/log/nginx/foobar.app-error.log;

    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass http://unix:/home/foobar/.unicorn.sock;
  }
}
```

Assuming you receive document uploads at `POST /documents`, to check them with
a Clammit that has been configured to listen on an UNIX socket in
`/var/run/clammit.sock`, you should add a location block like this:

```nginx
  location /documents {
    access_log /var/log/nginx/foobar.clammit-access.log;
    error_log  /var/log/nginx/foobar.clammit-error.log;

    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    # This is where clammit will forward requests that do not contain viruses
    # or that did not contain any data to scan.
    proxy_set_header X-Clammit-Backend unix:/home/foobar/.unicorn.sock;

    proxy_pass http://unix:/var/run/clammit.sock;
  }
```

All requests to `/documents` will then pass through Clammit, and uploads will
be scanned for viruses. To your application the request will just appear as
coming from Nginx, all cookies and the headers will be kept intact.

If a virus is detected, Clammit will reject the request (with a `418` status
code), and not forward it to your application. If you use an AJAX uploader, you
can interpret this response and show a nice error message to end users. Or you
could set a custom error page in Nginx.

### Usage as a service

When used as a service, clammit can be anywhere in your architecture, and it will
return a 200 OK if the request has no virus, or a configurable status code if a
virus is detected.

To scan a file, send it via HTTP - using any method you prefer - to the
`/clammit/scan` endpoint.

Example, with cURL:

```sh
curl -sf http://localhost:8438/clammit/scan -d @/some/file
```

Or with Python:

```py
import requests

>>> r = requests.post('http://localhost:8438/clammit/scan', files={'file': open('/etc/passwd', 'rb')})
>>> r.status_code
200

>>> r = requests.post('http://localhost:8438/clammit/scan', files={'file': b'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'})
>>> r.status_code
418
```

Or with Ruby:

```ruby
require 'httparty'

>> r = HTTParty.post('http://localhost:8438/clammit/scan', body: { file: File.open('/etc/passwd') })
>> r.code
=> 200

>> r = HTTParty.post('http://localhost:8438/clammit/scan', multipart: true, body: { file: 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' })
>> r.code
=> 418
```

## Configuration

You will need to create and edit a configuration file. An example is found in etc.sample/

The configuration is pretty simple:

```ini
[ application ]
listen          = :8438
application-url = http://host:port/path
clamd-url       = http://host:port/
log-file        = /var/log/clammit.log
debug           = true
test-pages      = true
```

Setting                  | Description
:------------------------| :-----------------------------------------------------------------------------
listen                   | The listen address (see below)
unix-socket-perms        | The file mode of the UNIX socket, if listening on one
clamd-url                | The URL of the clamd server
virus-status-code        | (Optional) The HTTP status code to return when a virus is found. Default 418
application-url          | (Optional) Forward all requests to this application
content-memory-threshold | (Optional) Maximum payload size to keep in RAM. Larger files are spooled to disk
log-file                 | (Optional) The clammit log file, if omitted will log to stdout
test-pages               | (Optional) If true, clammit will also offer up a page to perform test uploads
debug                    | (Optional) If true, more things will be logged

The listen address can be a TCP port or Unix socket, e.g.:

* `0.0.0.0:8438`               - Listen on all IPs on port 8438
* `unix:/var/run/clammit.sock` - Listen on a Unix socket

The same format applies to the `clamd-url` and `application-url` parameters.

By default Clammit will look for a `X-Clammit-Backend` header, and use that to
decide where to send requests to. If you only have one backend server, you can
set it in the `application-url` configuration option, and omit the header.

## Architecture

Flow-wise, Clammit is straightforward. It sets up an HTTP server to accept
incoming requests (main.go):

1. Each request is passed to the forwarder (forwarder/forwarder.go)
2. The forwarder downloads the request body (as it will be used at least twice)
3. The forwarder passes the request to the clam interceptor (clam\_interceptor.go)
4. The only request that will be tested will have methods POST/PUT/PATCH
5. The clam interceptor locates and sends each form-data field to ClamD
6. For any positive response, the interceptor will write an HTTP response and return (and the forwarder will not attempt to forward the request)
7. If the interceptor OKs the request, the forwarder constructs a new HTTP request and forwards to the application
8. The application's response is returned as the response to the original request

## Building

Clammit requires the Go compiler, version 1.15 or above. It also requires `make`
to ease compilation. The makefile is pretty simple, though, so you can perform its
steps manually if you want.

You will need external access to github and code.google.com to load the
third-party packages that Clammit depends on: [go-clamd][] and [gcfg][].

Once you have this, simply run:

```sh
make
```
This will download the third-party packages and compile Clammit. The resulting
binary is found in the bin directory.

Other make options are:

Option            | Description
:-----------------| :------------------------------------------------------------------------
make clean        | Removes the compiled binary and intermediate libraries (in pkg/)
make cleanimports | Removes the downloaded third-party source packages
make gets         | Downloads the third-party source packages, if they are not already there
make test         | Runs the application unit tests

## Installation

1. Copy the compiled binary (bin/clammit), either into your project repository, or to an installation area.
2. Edit the configuration file as appropriate.
3. Configure your auto-start mechanism, be it God or init.d. An example systemd unit is provided.
4. Configure the upstream webserver to forward appropriate POST requests to clammit.

## API

Clammit's own actions are grouped under the "/clammit" path. You should ensure
that these are not available externally.

### Info

```
  GET /clammit
```

This method will return JSON giving the current status of Clammit and its connection to ClamAV.

### Scan

```
  POST /clammit/scan
```

This is the endpoint to submit files for scanning only. Any files to be scanned should be attached as file objects.
Clammit will return an HTTP status code of 200 if the request is clean and 418 if there is a bad attachment.

### Ready

```
  GET /clammit/readyz
```

Returns 200 OK unless we are shutting down, waiting for currently running requests to complete.

Clammit does not implement a liveness check, as clammit is available if its TCP socket is open.

### Test

```
  GET /clammit/test/
```

This will return a simple file upload page, to test sending requests to Clammit. These pages are located in the
testing/ sub-directory.

## Web app

In the web/ directory is a simple Sinatra server to act as the application (for testing purposes).

## Tests

Run ```make test```

## Limitations

* Clammit does not implement HTTPS, as it is not intended to be a front-line server.
* It does not attempt to recursively scan fields - e.g. attachments in an email chain
* It does not try to be particularly clever with storing the body, which means that a DOS attack by hitting it simultaneously with a gazillion small files is quite possible.

## License

[MIT](https://github.com/ifad/clammit/blob/master/LICENSE)

[gcfg]:                http://code.google.com/p/gcfg
[go-clamd]:            http://github.com/dutchcoders/go-clamd
