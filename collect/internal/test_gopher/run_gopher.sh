#!/bin/bash

BASE=/home/dev/go/src/
cd $BASE || { echo "no such dir."; exit 1; }

# Create results directory
RESULTS_DIR="$BASE/test/scan-results"
mkdir -p "$RESULTS_DIR"

chmod +x $BASE/gopher/gopher
PROJECTS_DIR="$BASE/test/projects"

if [ ! -d "$PROJECTS_DIR" ]; then
    echo "Error: Projects directory not found at $PROJECTS_DIR"
    exit 1
fi

for project in "$PROJECTS_DIR"/*; do
    if [ -d "$project" ]; then
        echo "Running gopher on project: $(basename "$project")"
        ./gopher/gopher "$project"
        if [ $? -ne 0 ]; then
            echo "Error: Failed to run gopher on project $(basename "$project")"
        else
            # Move scan-results to a common directory
            if [ -d "$project/scan_results" ]; then
                mv "$project/scan_results" "$RESULTS_DIR/$(basename "$project")-scan_results"
            fi
        fi
    fi
done

# Rename .txt files to .json in the common scan-results directory
for result_file in "$RESULTS_DIR"/*/*.txt; do
    if [ -f "$result_file" ]; then
        mv "$result_file" "${result_file%.txt}.json"
    fi
done

# Remove JSON objects containing "test" in the sourceFileName
for json_file in "$RESULTS_DIR"/*.json; do
    if [ -f "$json_file" ]; then
        jq 'del(.[] | select(.Slicing_Criteria.SourceFilename | contains("test"))) ' "$json_file" > tmp.json && mv tmp.json "$json_file"
    fi
done


