#!/bin/sh

# Build the docker image
docker build -t ftp-server .

# run the ftp server instance
docker run --rm --name ftp-server -ti --net=host ftp-server
