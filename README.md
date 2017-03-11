# Clammit

[![Build Status](https://travis-ci.org/ifad/clammit.svg)](https://travis-ci.org/ifad/clammit)
[![Code Climate](https://codeclimate.com/github/ifad/clammit/badges/gpa.svg)](https://codeclimate.com/github/ifad/clammit)

Clammit is a proxy that will perform virus scans of files uploaded via http requests,
including `multipart/form-data`.  If a virus exists, it will reject the request out of
hand. If no virus exists, the request is then forwarded to the application and
it's response returned in the upstream direction.

As the name implies, Clammit offloads the virus detection to the ClamAV virus
detection server (clamd).

## Usage

Clammit is intended to be used as an internal proxy, a sort of middleware. It
is best to only pass requests that include a file upload, however requests that
aren't `POST`/`PUT`/`PATCH` are passed through directly without being scanned.

As an example, say you have a Rails application that is configured in Nginx
like this:

```nginx
set $my_app /myapp;

server {
  listen 80;
  server_name my_app.com;

  root $my_app/public;
  try_files $uri/index.html $uri @app;

  location @app {
    access_log /var/log/nginx/my_app-access.log;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass http://unix:$my_app/.unicorn.sock;
  }

  error_page 500 502 503 504 /500.html;
  client_max_body_size 4G;
  keepalive_timeout 10;
}
```

Assuming you receive document uploads at `POST /documents`, to check them with
Clammit add another location block like this:

```nginx
  set $clammit_app /clammit;

  location /documents {
    access_log /var/log/nginx/my_app-access.log;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Clammit-Backend unix:$my_app/.unicorn.sock;
    proxy_pass http://unix:$clammit_app/.unicorn.sock;
  }
```

All requests to `/documents` will then pass through Clammit, and uploads will
be scanned for viruses. To your application the request will just appear as
coming from Nginx, all cookies and the headers will be kept intact.

If a virus is detected, Clammit will reject the request (with a `418` status
code), and not forward it to your application. If you use an AJAX uploader, you
can interpret this response and show a nice error message to end users. Or you
could set a custom error page in Nginx.

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

Setting         | Description
:---------------| :-----------------------------------------------------------------------------
listen          | The listen address (see below)
clamd-url       | The URL of the clamd server
application-url | (Optional) Forward all requests to this application
log-file        | (Optional) The clammit log file, if ommitted will log to stdout
test-pages      | (Optional) If true, clammit will also offer up a page to perform test uploads
debug           | (Optional) If true, more things will be logged
debug-clam      | (Optional) If true, the response from ClamAV will be logged

The listen address can be a TCP port or Unix socket, e.g.:

* `0.0.0.0:8438`       - Listen on all IPs on port 8438
* `unix:.clammit.sock` - Listen on a Unix socket

The same format applies to the `clamd-url` and `application-url` parameters.

By default Clammit will look for a `X-Clammit-Backend` header, and use that to
decide where to send requests to. If you only have one backend server, you can
set it in the `application-url` configuration option, and omit the header.

## Architecture

Flow-wise, Clammit is straightforward. It sets up an HTTP server to accept
incoming requests (main.go):

1. Each request is passed to the forwarder (forwarder/forwarder.go)
2. The forwarder dowloads the request body (as it will be used at least twice)
3. The forwarder passes the request to the clam interceptor (clam\_interceptor.go)
4. The only request that will be tested will have methods POST/PUT/PATCH and content-type "multipart/form-data"
5. The clam interceptor locates and sends each form-data field to ClamD
6. For any positive response, the interceptor will write an HTTP response and return (and the forwarder will not attempt to forward the request)
7. If the interceptor OKs the request, the forwarder constructs a new HTTP request and forwards to the application
8. The application's response is returned as the response to the original request

## Building

Clammit is requires the Go compiler, version 1.2 or above. It also requires ```make```
to ease compilation. The makefile is pretty simple, though, so you can perform its
steps manually if you want.

You will need external access to github and code.google.com to load the
third-party packages that Clammit depends on: [go-clamd][] and [gcfg][].

Once you have this, simple run:

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
3. Configure your auto-start mechanism, be it God or init.d
4. Configure the upstream webserver to forward appropriate POST requests to clammit.

## API

Clammit's own actions are grouped under the "/clammit" path. You should ensure
that these are not available externally.

### Info

```
  GET /clammit/info
```

This method will return JSON giving the current status of Clammit and its connection to ClamAV.

### Scan

```
  POST /clammit/scan
```

This is the endpoint to submit files for scanning only. The request must have content-type ```multipart/form-data```
and any files to be scanned should be attached as file objects. Clammit will return an HTTP status code of 200 if
the request is clean and 418 if there is a bad attachment.

### Test

```
  GET /clammit/test/
```

This will return a simple file upload page, to test sending requests to Clammit. These pages are located in the
testing/ subdirectory.

## Resources

In the resources/ directory is a simple Sinatra server to act as the application (for testing purposes).

## Tests

Run ```make test```

## Limitations

* Clammit does not implement HTTPS, as it is not intended to be a front-line server.
* It does not attempt to recursively scan fields - e.g. attachments in an email chain
* It does not try to be particularly clever with storing the body, which means that a DOS attack by hitting it simultaneously with a gazillion small files is quite possible.

## Licence

[MIT](https://github.com/ifad/clammit/blob/master/LICENSE)

[gcfg]:                http://code.google.com/p/gcfg
[go-clamd]:            http://github.com/dutchcoders/go-clamd
