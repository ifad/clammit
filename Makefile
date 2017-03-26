export GOPATH=$(PWD)
export GO15VENDOREXPERIMENT=1

all:	gets application

test: gets
	go test clammit/...

clean:
	rm bin/clammit
	rm -rf pkg/*

cleanimports:
	rm -rf src/gopkg.in
	rm -rf src/github.com

application:
	cd src/clammit && go install


gets:	gcfg testify go-clamd

gcfg:
	[ -d src/gopkg.in/gcfg.v1 ] || go get gopkg.in/gcfg.v1

go-clamd:
	[ -d src/github.com/Freeaqingme/go-clamd ] || go get github.com/Freeaqingme/go-clamd

testify:
	[ -d src/gopkg.in/testify.v1 ] || go get gopkg.in/stretchr/testify.v1
