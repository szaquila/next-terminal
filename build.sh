#!/bin/bash

cp build/resources/logo.png web/src/images/logo.png
cp build/resources/logo-with-name.png web/src/images/logo-with-name.png
cp build/resources/favicon.ico web/public/favicon.ico

rm -rf server/resource/build
echo "clean build history"

echo "build web..."
cd web || exit
yarn build || exit
cp -r build ../server/resource/
echo "build web success"

echo "build api..."
cd ..
go env;CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -o next-terminal main.go
# CC=x86_64-linux-musl-gcc go build -tags libsqlite3 -tags musl -ldflags '-linkmode external -extldflags "-static" -s -w' -o next-terminal main.go
upx next-terminal

rm -rf server/resource/build
echo "build api success"
