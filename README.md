# Clammit

[![Build Status](https://travis-ci.org/ifad/clammit.svg)](https://travis-ci.org/ifad/clammit)

Clammit is a stand-alone application with just one task, to stand between
the client and application and to virus-check the files in the client request.
If a virus exists, it will reject the request out of hand. If no virus exists,
the request is then forwarded to the application and its response returned in
the upstream direction.

As the name implies, Clammit offloads the virus detection to the ClamAV virus
detection server (clamd).

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

## Running

You will need to create and edit a configuration file. An example is found in etc.sample/

The configuration is pretty simple:

```ini
  [ application ]
  listen          = :8438
  application-url = http://host:port/path
  clamd-url       = http://host:port/
  log-file        = /var/log/clammit.log
  test-pages      = true
```

Setting         | Description
:---------------| :-----------------------------------------------------------------------------
listen          | The listen address (see below)
application-url | The URL to forward the request to (including path!)
clamd-url       | The URL of the clamd server
log-file        | (Optional) The clammit log file
test-pages      | (Optional) If true, clammit will also offer up a page to perform test uploads

### Listen address

This configuration setting allows you to specify TCP address:port or Unix socket filename.
You can specify one of these forms:

* tcp:host:port        (listens on one TCP interface, IPv4 and IPv6)
* tcp:port             (listens on all interfaces)
* tcp4:host:port       (listens on one TCP4 interface)
* tcp4:port            (listens on all TCP4 interfaces)
* tcp6:[host]:port     (listens on one TCP6 interface)
* tcp6:port            (listens on all TCP6 interfaces)
* unix:filename        (listen on Unix socket)
* host:port            (assumes TCP)
* :port                (assumes TCP)

If you wish to only listen on IPv6 addresses with the tcp: scheme, the
host should be encapsulated within brackets, e.g. tcp:[::1]:1234

Using scheme unix:, Clammit will abort with an error "bind: address already in
 use" if the socket file exists. It will delete it on shutdown.

## Installation

1. Copy the compiled binary (bin/clammit), either into your project repository, or to an installation area.
2. Edit the configuration file as appropriate.
3. Configure your auto-start mechanism, be it God or init.d
4. Configure the upstream webserver to forward appropriate POST requests to clammit.

## Calling Clammit

Clammit's own actions are grouped under the "/clammit" path (see below). Any
other request will be scanned (POST and PUT only) then forwarded to the
application.

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
