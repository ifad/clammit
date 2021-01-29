export GOPATH=$(PWD)

all:	gets application

linux:
	GOOS=linux GOARCH=amd64 make application

test: gets
	cd src/clammit && go test clammit/...

delve:
	go get github.com/go-delve/delve/cmd/dlv

debug: delve
	cd src/clammit && $(GOPATH)/bin/dlv debug clammit

debug-test: delve
	cd src/clammit && $(GOPATH)/bin/dlv test clammit

fmt:
	go fmt clammit/...

clean:
	rm bin/clammit
	rm -rf pkg/*

application:
	cd src/clammit && go install

gets:
	cd src/clammit && go get

release:
	curl -sL https://git.io/goreleaser | bash
