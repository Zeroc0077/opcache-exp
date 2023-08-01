#!/bin/sh

docker build -t php74debug .
docker run -it -d --name debug -p 8080:80 -p 2222:22 php74debug:latest
