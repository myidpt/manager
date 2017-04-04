#!/bin/bash
set -ex

buildifier -showlog -mode=check $(find . -type f \( -name 'BUILD' -or -name 'WORKSPACE' -or -wholename '.*bazel' -or -wholename '.*bzl' \) -print )

go generate ./...

NUM_CPU=$(getconf _NPROCESSORS_ONLN)

gometalinter --concurrency=${NUM_CPU} --enable-gc --deadline=300s --disable-all\
  --enable=aligncheck\
  --enable=deadcode\
  --enable=errcheck\
  --enable=gas\
  --enable=goconst\
  --enable=gofmt\
  --enable=goimports\
  --enable=golint\
  --exclude=.pb.go\
  --exclude=gen_test.go\
  --enable=gosimple\
  --enable=gotype\
  --enable=ineffassign\
  --enable=interfacer\
  --enable=lll --line-length=120\
  --enable=misspell\
  --enable=staticcheck\
  --enable=structcheck\
  --enable=unconvert\
  --enable=unused\
  --enable=varcheck\
  --enable=vet\
  --enable=vetshadow\
  ./...

# Disabled linters:
# --enable=dupl\
# --enable=gocyclo\
# --cyclo-over=15\
