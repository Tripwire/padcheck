#!/bin/sh

./go-go1.11/bin/go install -v crypto/tls && ./go-go1.11/bin/go build -o padcheck padcheck.go
