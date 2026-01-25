#!/bin/bash

# Script for running tool analysis with scheduling

if ! command -v parallel &> /dev/null; then
    echo "GNU Parallel is required but not installed. Please install it first."
    exit 1
fi

# Check input
if [ $# -ne 4 ]; then
  echo "Usage: $0 <dataset path> <docker-compose YAML> <max parallel jobs> <comma-separated tools>"
  echo "Example: $0 dataset.json docker-compose.yml 4 codeql,gopher,gosec"
  exit 1
fi

DATASET=$1
DOCKER_YAML=$2
MAX_PARALLEL=$3
TOOLS_STR=$4

# Validate tools input
if [[ ! "$TOOLS_STR" =~ ^[a-zA-Z0-9_,]+$ ]]; then
    echo "Error: Tools must be comma-separated and contain only alphanumeric characters"
    exit 1
fi

# Convert comma-separated tools string to array
IFS=',' read -ra TOOLS <<< "$TOOLS_STR"

# Validate each tool
for tool in "${TOOLS[@]}"; do
    if [ -z "$tool" ]; then
        echo "Error: Empty tool name found in tools list"
        exit 1
    fi
done

if [ ! -f "$DATASET" ]; then
  echo "Error: Dataset file $DATASET does not exist"
  exit 1
fi

if [ ! -f "$DOCKER_YAML" ]; then
  echo "Error: File $DOCKER_YAML does not exist"
  exit 1
fi

# timestamp for this run
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "results_${TIMESTAMP}"
RESULTS_DIR="results_${TIMESTAMP}"
PROJECT_NAME="cryptoapi_${TIMESTAMP}"  # Unique project name for this run

# global log files
GLOBAL_LOG="${RESULTS_DIR}/global.log"
SUMMARY_FILE="${RESULTS_DIR}/summary.txt"
touch "$GLOBAL_LOG"
touch "$SUMMARY_FILE"

# Export for parallel environment
export RESULTS_DIR DOCKER_YAML MAX_PARALLEL DATASET GLOBAL_LOG SUMMARY_FILE PROJECT_NAME # Export for parallel environment



echo "=== Starting tool analysis at $(date) ===" | tee -a "$GLOBAL_LOG"
echo "Maximum parallel jobs: $MAX_PARALLEL" | tee -a "$GLOBAL_LOG"

# run a single service container
run_service() {
    local tool=$1
    local service=$2
    local tool_dir="${RESULTS_DIR}/${tool}"
    local service_log="${tool_dir}/${service}.log"
    local service_error="${tool_dir}/${service}.err"
    local project_name="${PROJECT_NAME}_${tool}_${service}"  # Include service name for unique networks
    
    mkdir -p "$tool_dir"
    
    echo "[$(date +%H:%M:%S)] Starting ${tool} analysis for service: ${service}" | tee -a "$GLOBAL_LOG"
    
    # Build and run just the single service
    if docker-compose -f "$DOCKER_YAML" --project-name "$project_name" build "$service" > "${service_log}" 2> "${service_error}"; then
        # Track start time
        start_time=$(date +%s)
        
        # Run with timeout
        if timeout 30m docker-compose -f "$DOCKER_YAML" --project-name "$project_name" up --no-deps "$service" >> "${service_log}" 2>> "${service_error}"; then
            status="SUCCESS"
        else
            exit_code=$?
            if [ $exit_code -eq 124 ]; then
                status="TIMEOUT"
            else
                status="FAILED"
            fi
        fi
        
        # Track end time and calculate duration
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        
        # Clean up this specific container and its network
        docker-compose -f "$DOCKER_YAML" --project-name "$project_name" rm -f "$service" >> "${service_log}" 2>> "${service_error}"
        docker network rm "${project_name}_default" >> "${service_log}" 2>> "${service_error}" || true  # Ignore if network doesn't exist
        
        echo "[$(date +%H:%M:%S)] Completed ${tool}:${service} - Status: ${status}, Duration: ${duration}s" | tee -a "$GLOBAL_LOG" "${tool_dir}/summary.txt"
        return 0
    else
        # Clean up on failure
        docker-compose -f "$DOCKER_YAML" --project-name "$project_name" rm -f "$service" >> "${service_log}" 2>> "${service_error}"
        docker network rm "${project_name}_default" >> "${service_log}" 2>> "${service_error}" || true  # Ignore if network doesn't exist
        echo "[$(date +%H:%M:%S)] Failed to build ${tool}:${service}\nCMD: docker-compose -f \"$DOCKER_YAML\" --project-name \"$project_name\" build \"$service\"" | tee -a "$GLOBAL_LOG" "${tool_dir}/summary.txt"
        return 1
    fi
}
export -f run_service

# Function to run a tool with all its services
run_tool() {
    local tool=$1
    local tool_log="${RESULTS_DIR}/${tool}/progress.log"
    local tool_error="${RESULTS_DIR}/${tool}/error.log"
    local tool_time="${RESULTS_DIR}/${tool}/time.txt"
    local tool_parallel=$MAX_PARALLEL
    
    mkdir -p "${RESULTS_DIR}/${tool}"
    
    # decrease parallel value for codeql (requires more resources)
    if [ "$tool" = "codeql" ]; then
        tool_parallel=$((MAX_PARALLEL - 3))
        echo "[$(date +%H:%M:%S)] Using reduced parallel value of ${tool_parallel} for codeql (original: ${MAX_PARALLEL})" | tee -a "$GLOBAL_LOG" "$tool_log"
    fi
    
    echo "[$(date +%H:%M:%S)] === Starting analysis with tool: ${tool} ===" | tee -a "$GLOBAL_LOG" "$tool_log"
    
    # generate Docker Compose file for this tool
    echo "[$(date +%H:%M:%S)] Generating Docker Compose for ${tool}..." | tee -a "$GLOBAL_LOG" "$tool_log"
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
    if ! go run "${REPO_ROOT}/cmd/compose" -out-dir "$RESULTS_DIR" -verbose -tools "${tool}" "${DATASET}"; then
        echo "[$(date +%H:%M:%S)] Failed to generate Docker Compose for ${tool}. Exiting..." | tee -a "$GLOBAL_LOG" "$tool_error"
        return 1
    fi
    
    # get list of services defined in the file
    SERVICES=$(docker-compose -f "$DOCKER_YAML" config --services)
    TOTAL=$(echo "$SERVICES" | wc -l)
    
    echo "[$(date +%H:%M:%S)] Found ${TOTAL} services to analyze with ${tool}" | tee -a "$GLOBAL_LOG" "$tool_log"
    
    # start timing the execution
    start_time=$(date +%s)
    
    # use parallel to run services with parallelism 'tool_parallel'
    echo "$SERVICES" | parallel --will-cite -j "$tool_parallel" run_service "$tool" {}
    
    # end timing
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    echo "Total execution time for ${tool}: ${duration} seconds" | tee -a "$tool_time" "$GLOBAL_LOG"
    echo "[$(date +%H:%M:%S)] === Completed analysis with tool: ${tool} ===" | tee -a "$GLOBAL_LOG" "$tool_log"
    
    # summary
    echo "${tool}: ${duration} seconds (${TOTAL} services)" >> "$SUMMARY_FILE"
    
    # Clean up any remaining containers for this tool's services
    for service in $SERVICES; do
        local project_name="${PROJECT_NAME}_${tool}_${service}"
        docker-compose -f "$DOCKER_YAML" --project-name "$project_name" down --remove-orphans
    done
    
    return 0
}

# run each tool sequentially with parallel execution within each tool
for tool in "${TOOLS[@]}"; do
    run_tool "${tool}"
done

# Final cleanup for all services of all tools
for tool in "${TOOLS[@]}"; do
    SERVICES=$(docker-compose -f "$DOCKER_YAML" config --services)
    for service in $SERVICES; do
        local project_name="${PROJECT_NAME}_${tool}_${service}"
        docker-compose -f "$DOCKER_YAML" --project-name "$project_name" down --volumes --remove-orphans
    done
done

echo "[$(date +%H:%M:%S)] All tools completed. Results are in ${RESULTS_DIR}/" | tee -a "$GLOBAL_LOG"
echo "=== Analysis Summary ===" | tee -a "$GLOBAL_LOG" "$SUMMARY_FILE"
cat "$SUMMARY_FILE" | tee -a "$GLOBAL_LOG"
