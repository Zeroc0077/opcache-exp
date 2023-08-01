#!/bin/sh
docker build --rm -t php82-opcache .
docker run --name php82 -d -p 8080:80 php82-opcache:latest
