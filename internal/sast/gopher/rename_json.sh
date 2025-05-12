#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 /path/to/directory"
  exit 1
fi

DIR="$1"

if [ ! -d "$DIR" ]; then
  echo "Directory $DIR does not exist."
  exit 1
fi

find "$DIR" -type f -name "*.txt" | while read -r FILE; do
  mv "$FILE" "${FILE%.txt}.json" || exit 1
done


echo "Renaming complete."
