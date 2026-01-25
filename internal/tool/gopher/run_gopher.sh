#!/bin/sh
cd /analysis/gopher || exit 1

# Create log directory if it doesn't exist
TARGET_DIR="/analysis/results/gopher"
TIMING_LOG="$TARGET_DIR/timing.json"
mkdir -p "$TARGET_DIR" || { echo "Failed to create target directory $TARGET_DIR"; exit 1; }

# Initialize timing log with JSON array opening bracket
echo "[" > "$TIMING_LOG"

# Run gopher and capture both stdout and stderr to a log file
START_TIME=$(date +%s)
./gopher /analysis/repo > "$TARGET_DIR/gopher.log" 2>&1
GOPHER_EXIT_CODE=$?
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

printf '{"stage":"gopher_analysis","start_time":%s,"end_time":%s,"duration_seconds":%s,"exit_code":%s}' \
  "$START_TIME" "$END_TIME" "$DURATION" "$GOPHER_EXIT_CODE" >> "$TIMING_LOG"

if [ $GOPHER_EXIT_CODE -ne 0 ]; then
    echo "Gopher scan failed with exit code $GOPHER_EXIT_CODE. Check $TARGET_DIR/gopher.log for details."
fi

DIR="/analysis/repo/scan_results"

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

# Then move all .json files to the target directory (results + metadata)
find "$DIR" -type f -name "*.json" | while read -r FILE; do
  mv "$FILE" "$TARGET_DIR/" || exit 1
done

# Close the JSON array in the timing log
echo "]" >> "$TIMING_LOG"
