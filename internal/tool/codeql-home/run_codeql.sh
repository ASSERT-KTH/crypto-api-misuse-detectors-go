#!/bin/sh

RESULTS_DIR=/analysis/results/codeql
TIMING_LOG=$RESULTS_DIR/timing.json
ERROR_LOG_DIR=$RESULTS_DIR/errors
QUERY_BASE_PATH="/analysis/codeql-home/codeql/qlpacks/codeql/go-queries/1.1.13/Security"

# Create results directory and error log directory if they don't exist
mkdir -p "$RESULTS_DIR" "$ERROR_LOG_DIR" || exit 1

# CSV headers for result files
CSV_HEADERS="Name,Description,Severity,Message,Path,Start line,Start column,End line,End column"

# Initialize JSON file with empty array
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
    
    return $exit_code
}

# Function to add CSV headers to a file
add_csv_headers() {
    local file="$1"
    if [ -f "$file" ] && [ -s "$file" ]; then
        # Create a temporary file with headers
        echo "$CSV_HEADERS" > "$file.tmp"
        # Append the original content
        cat "$file" >> "$file.tmp"
        # Replace the original with the temporary file
        mv "$file.tmp" "$file"
    fi
}

# Time and create database
time_to_json "/analysis/codeql-home/codeql/codeql database create --language=go --source-root=/analysis/repo /analysis/db/" "database_creation" || exit 1

# Add comma between entries
echo "," >> "$TIMING_LOG"

# CWEs to analyze
CWES="338 326 327 322 295 347" # removed 798 -- not crypto relevant enough

# Start timing the analysis phase
start_time=$(date +%s)

# Run individual CWE analyses
for cwe in $CWES; do
    echo "Running analysis for CWE-$cwe..."
    
    # Specific path for the CWE query directory
    cwe_dir="$QUERY_BASE_PATH/CWE-$cwe"
    
    if [ ! -d "$cwe_dir" ]; then
        echo "No query directory found for CWE-$cwe at $cwe_dir" > "$ERROR_LOG_DIR/CWE-${cwe}-missing-directory.log"
        continue
    fi
    
    # Find the QL files directly in the CWE directory
    for query_file in "$cwe_dir"/*.ql; do
        # Skip if no files match the pattern
        if [ ! -f "$query_file" ]; then
            echo "No query files found in directory $cwe_dir" > "$ERROR_LOG_DIR/CWE-${cwe}-no-queries.log"
            continue 2  # Continue the outer loop
        fi
        
        query_name=$(basename "$query_file" .ql)
        output_file="$RESULTS_DIR/CWE-${cwe}_${query_name}.csv"
        error_file="$ERROR_LOG_DIR/CWE-${cwe}_${query_name}-error.log"
        
        echo "Running query: $query_file"
        /analysis/codeql-home/codeql/codeql database analyze \
          /analysis/db \
          "$query_file" \
          --format=csv \
          --output="$output_file" || {
            echo "Analysis failed for $query_file" > "$error_file"
            echo "Command: /analysis/codeql-home/codeql/codeql database analyze /analysis/db $query_file --format=csv --output=$output_file" >> "$error_file"
            echo "Exit code: $?" >> "$error_file"
            continue
          }
        
        # If analysis succeeded but file is empty (no findings), remove the file
        if [ -f "$output_file" ] && [ ! -s "$output_file" ]; then
            rm "$output_file"
        else
            # Add CSV headers to the output file
            add_csv_headers "$output_file"
        fi
    done
done

# Calculate total analysis time
end_time=$(date +%s)
duration=$((end_time - start_time))

# Record combined analysis timing
printf '{"stage":"analysis","start_time":%s,"end_time":%s,"duration_seconds":%s,"exit_code":0}' \
    "$start_time" "$end_time" "$duration" >> "$TIMING_LOG"

# Close JSON array
echo "]" >> "$TIMING_LOG"

# Move logs and run info
mv /analysis/db/log $RESULTS_DIR 2>/dev/null || true
mv /analysis/db/results/run-info*.yml $RESULTS_DIR/log 2>/dev/null || true


# Had to put archiving somewhere, and now it is here
# Create a timestamp for unique archive name
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

cd /analysis
tar --exclude='repo/.git' --exclude='repo/*.tar.gz' -czf "$TARGET_DIR/$ARCHIVE_NAME" repo