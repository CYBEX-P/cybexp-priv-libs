#!/usr/bin/env bash

DOCKERFILE_LOC=~/Projects/cybexp-privacy/

DOCKER_STATE=`sudo systemctl status docker | grep Active: | head -n 1 | awk '{print $2}'`

if [ "$DOCKER_STATE" = "inactive" ]; then
   echo "Starting docker service..."
   sudo systemctl start docker
   exec $0
elif [ "$DOCKER_STATE" = "active" ]; then
   docker build -t cybexp-collector $DOCKERFILE_LOC && docker run -it cybexp-collector /bin/bash
else
   echo 'Failed...'
   exit 1
fi

