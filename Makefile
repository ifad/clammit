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

gets:	gcfg testify

gcfg:
	[ -d src/gopkg.in/gcfg.v1 ] || go get gopkg.in/gcfg.v1

testify:
	[ -d src/gopkg.in/testify.v1 ] || go get gopkg.in/stretchr/testify.v1

release:
	curl -sL https://git.io/goreleaser | bash