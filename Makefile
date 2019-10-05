PKG:=github.com/kayrus/ingress-terraform
APP_NAME:=terraform-ingress-controller
PWD:=$(shell pwd)
UID:=$(shell id -u)

export GO111MODULE:=off
export GOPATH:=$(PWD):$(PWD)/gopath
export CGO_ENABLED:=0

build: gopath/src/$(PKG) fmt
	cd gopath/src/$(PKG) && GOOS=linux go build -o bin/$(APP_NAME) ./cmd

docker:
	docker run -ti --rm -e GOCACHE=/tmp -v $(PWD):/$(APP_NAME) -u $(UID):$(UID) --workdir /$(APP_NAME) golang:latest make

fmt:
	gofmt -s -w ./pkg

vet: gopath/src/$(PKG) fmt
	cd gopath/src/$(PKG) && go vet ./...

gopath/src/$(PKG):
	test -d vendor || GOPATH= GO111MODULE=auto go mod vendor
	mkdir -p gopath/src/$(shell dirname $(PKG))
	ln -sf ../../../.. gopath/src/$(PKG)
