export GOPATH=$(PWD)

all:	gets application

test:
	@go test clammit/...

clean:
	@rm bin/clammit
	@rm -rf pkg/*

cleanimports:
	@rm -rf src/gopkg.in
	@rm -rf src/github.com

application:
	@cd src/clammit && go install

gets:	gcfg go-clamd

gcfg:
	@[ -d src/gopkg.in/gcfg.v1 ] || go get gopkg.in/gcfg.v1

go-clamd:
	@[ -d src/github.com/dutchcodes/go-clamd ] || go get github.com/dutchcoders/go-clamd
