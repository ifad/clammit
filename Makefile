all:	gets application

linux:
	GOOS=linux GOARCH=amd64 make application

test: gets
	go test ./...

delve:
	go get github.com/go-delve/delve/cmd/dlv

debug: delve
	go run github.com/go-delve/delve/cmd/dlv debug .

debug-test: delve
	go run github.com/go-delve/delve/cmd/dlv test ./...

fmt:
	go fmt ./...

clean:
	rm -rf dist/

application:
	go install

gets:
	go get

release:
	goreleaser release
