#!/usr/bin/env bash

DIR_PATH=`dirname $0`
FULL_PATH=`readlink --canonicalize $DIR_PATH`

DOCKERFILE_LOC=$FULL_PATH
DOCKER_STATE=`sudo systemctl status docker | grep Active: | head -n 1 | awk '{print $2}'`

if [ "$DOCKER_STATE" = "inactive" ]; then
   echo "Starting docker service..."
   sudo systemctl start docker
   exec $0
elif [ "$DOCKER_STATE" = "active" ]; then
   sudo docker build -t cybexp-collector $DOCKERFILE_LOC && sudo docker run -it cybexp-collector /bin/bash
   DOCKER_ID=`docker ps --all | grep cybexp-collector | awk '{print $1}'`
   echo "Removing container"
   # sudo docker stop $DOCKER_ID
   sudo docker rm $DOCKER_ID
else
   echo 'Failed...'
   exit 1
fi

