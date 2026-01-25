#!/bin/bash

DIR=$1

find $DIR -name 'repo_src*' -exec sh -c '
  for path do
    dir=$(dirname "$path")
    mv "$path" "$dir/../"
  done
' sh {} +

