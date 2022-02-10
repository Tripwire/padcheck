#!/bin/sh
wget https://github.com/golang/go/archive/go1.11.tar.gz && tar xf go1.11.tar.gz && cd go-go1.11 && patch -p1 < ../paddingmodes-go1.11.diff && cd src/ && GO111MODULE=auto ./make.bash && cd ../ && ./bin/go build -o ../padcheck ../padcheck.go
