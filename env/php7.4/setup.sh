#!/bin/sh
docker build --rm -t php74-opcache .
docker run --name php74 -d -p 8080:80 php74-opcache:latest
