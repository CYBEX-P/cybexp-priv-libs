#!/usr/bin/env bash

IMAGE_NAME=cybexp-priv-libs


DOCKER_ID=`docker ps | grep $IMAGE_NAME | awk '{print $1}'`

docker cp ./priv-libs ${DOCKER_ID}:/

