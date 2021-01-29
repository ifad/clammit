export GOPATH=$(PWD)

all:	gets application

test: gets
	cd src/clammit && go test clammit/...

clean:
	rm bin/clammit
	rm -rf pkg/*

application:
	cd src/clammit && go install

gets:
	cd src/clammit && go get

release:
	curl -sL https://git.io/goreleaser | bash
