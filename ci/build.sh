#!/bin/bash

set -eux

ORIG_PWD="${PWD}"

# Create our own GOPATH
export GOPATH="${ORIG_PWD}/go"

# Symlink our source dir from inside of our own GOPATH
mkdir -p "${GOPATH}/src/github.com/govau"
ln -s "${ORIG_PWD}/src" "${GOPATH}/src/github.com/govau/verifiable-logs"
cd "${GOPATH}/src/github.com/govau/verifiable-logs"

# Install go deps
dep ensure

# Generate proto and assets.go
go generate

# Build the things
go install github.com/govau/verifiable-logs/cmd/{verifiable-logs-server,submit-from-external,submit-rows-to-logs,verifiable-log-tool}

# Copy artefacts to output directory for log server
cp "${GOPATH}/bin/verifiable-logs-server" "${ORIG_PWD}/build/verifiable-logs-server/verifiable-logs-server"
cp "${ORIG_PWD}/src/deploy/verifiable-logs-server/Procfile" "${ORIG_PWD}/build/verifiable-logs-server/Procfile"
cp "${ORIG_PWD}/src/deploy/verifiable-logs-server/manifest.yml" "${ORIG_PWD}/build/verifiable-logs-server/manifest.yml"

# Copy artefacts to output directory for log submitter
cp "${GOPATH}/bin/submit-from-external" "${ORIG_PWD}/build/verifiable-submitter/submit-from-external"
cp "${ORIG_PWD}/src/deploy/submit-from-external/Procfile" "${ORIG_PWD}/build/submit-from-external/Procfile"
cp "${ORIG_PWD}/src/deploy/submit-from-external/manifest.yml" "${ORIG_PWD}/build/submit-from-external/manifest.yml"
