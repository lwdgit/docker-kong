#!/usr/bin/env bash

kong_id=`docker ps | grep "_kong " | awk '{print $1}'`
docker exec -it $kong_id kong reload