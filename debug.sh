#!/usr/bin/env bash

kong_id=`docker ps | grep kong:latest | awk '{print $1}'`
docker exec -it $kong_id kong reload