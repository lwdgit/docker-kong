#!/usr/bin/env bash

function escape_slashes {
  sed 's/\//\\\//g' 
}

function change_line {
  local OLD_LINE_PATTERN=$1; shift
  local NEW_LINE=$1; shift
  local FILE=$1

  local NEW=$(echo "${NEW_LINE}" | escape_slashes)
  sed -i .bak '/'"${OLD_LINE_PATTERN}"'/s/.*/'"${NEW}"'/' "${FILE}"
  mv "${FILE}.bak" /tmp/
}

plugins=$(ls kong-plugin/kong/plugins | sort -V | tr '\n' ',' | rev | cut -c 2- | rev)

change_line "KONG_CUSTOM_PLUGINS=.*" "KONG_CUSTOM_PLUGINS=$plugins" $(pwd)/compose/plugins.env

cd compose && docker-compose up $@