#!/usr/bin/env bash

IMAGE_NAME=cybexp-collector


DOCKER_ID=`docker ps | grep $IMAGE_NAME | awk '{print $1}'`

docker cp ./code ${DOCKER_ID}:/

