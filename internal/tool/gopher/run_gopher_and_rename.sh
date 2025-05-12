#!/bin/sh
cd /analysis/gopher || exit 1
./gopher /analysis/repo

DIR="/analysis/repo/scan_results"
TARGET_DIR="/analysis/results/gopher"

if [ ! -d "$DIR" ]; then
  echo "Directory $DIR does not exist."
  exit 1
fi

# Create target directory if it doesn't exist
mkdir -p "$TARGET_DIR" || { echo "Failed to create target directory $TARGET_DIR"; exit 1; }

# First rename all .txt files to .json
find "$DIR" -type f -name "*.txt" | while read -r FILE; do
  mv "$FILE" "${FILE%.txt}.json" || exit 1
done

# Then move all .json files to the target directory
find "$DIR" -type f -name "*.json" | while read -r FILE; do
  mv "$FILE" "$TARGET_DIR/" || exit 1
done
