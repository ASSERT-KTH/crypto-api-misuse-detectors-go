#!/bin/sh

RESULTS_DIR=/analysis/results/gosec
TIMING_LOG=$RESULTS_DIR/timing.json
ERROR_LOG_DIR=$RESULTS_DIR/errors
OUTFILE=$RESULTS_DIR/results.json

# Create results directory and error log directory if they don't exist
mkdir -p "$RESULTS_DIR" "$ERROR_LOG_DIR" || exit 1

touch "$OUTFILE" || exit 1

# Initialize timing log with JSON array opening bracket
echo "[" > "$TIMING_LOG"

# Function to convert time output to JSON
time_to_json() {
    local cmd="$1"
    local stage="$2"
    local start_time=$(date +%s)
    eval "$cmd"
    local exit_code=$?
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Create JSON entry (using printf for better control)
    printf '{"stage":"%s","start_time":%s,"end_time":%s,"duration_seconds":%s,"exit_code":%s}' \
        "$stage" "$start_time" "$end_time" "$duration" "$exit_code" >> "$TIMING_LOG"
    
    # Log errors if they occur
    if [ $exit_code -ne 0 ]; then
        echo "Command failed with exit code $exit_code" > "$ERROR_LOG_DIR/${stage}_error.log"
        echo "Failed command: $cmd" >> "$ERROR_LOG_DIR/${stage}_error.log"
        echo "Time of failure: $(date)" >> "$ERROR_LOG_DIR/${stage}_error.log"
    fi
    
    return $exit_code
}

time_to_json "/analysis/gosec/gosec -include=G106,G402,G403,G404,G407,G501,G502,G503,G504,G505,G506,G507 -fmt=json -out=$OUTFILE ./repo/..." "gosec_analysis" || exit 1

# If analysis succeeded but file is empty, create an empty results note
if [ -f "$OUTFILE" ] && [ ! -s "$OUTFILE" ]; then
    echo "{\"results\":[]}" > "$OUTFILE"
    echo "No GoSec findings" > "$RESULTS_DIR/no_findings.log"
fi

# Close the JSON array in the timing log
echo "]" >> "$TIMING_LOG"

# Move any logs from gosec
mkdir -p "$RESULTS_DIR/log" 2>/dev/null
find /analysis/gosec -name "*.log" -type f -exec cp {} "$RESULTS_DIR/log/" \; 2>/dev/null
