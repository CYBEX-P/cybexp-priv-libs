#!/usr/bin/env bash

DOCKER_ID=`docker ps | grep cybexp-collector | awk '{print $1}'`

docker cp ./code ${DOCKER_ID}:/

