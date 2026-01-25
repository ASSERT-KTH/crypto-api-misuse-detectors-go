#!/bin/bash

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

# Default timeout values (in seconds)
DOCKER_BUILD_TIMEOUT=600  # 10 minutes
DOCKER_RUN_TIMEOUT=1800   # 30 minutes

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

# Function to check if docker command is available
check_docker() {
  if ! command -v docker &> /dev/null; then
    echo "ERROR: docker command not found" | tee -a "$ERROR_LOG"
    return 1
  fi
  
  if ! command -v docker-compose &> /dev/null; then
    echo "ERROR: docker-compose command not found" | tee -a "$ERROR_LOG"
    return 1
  fi
  
  return 0
}

# timestamp for this run
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="results_${TIMESTAMP}"
PROJECT_NAME="cryptoapi_${TIMESTAMP}"  # Unique project name for this run

# Function to set up directory structure and files
setup_directories() {
    # Create main results directory
    mkdir -p "$RESULTS_DIR"
    
    # Create global log files
    GLOBAL_LOG="${RESULTS_DIR}/global.log"
    ERROR_LOG="${RESULTS_DIR}/error.log"
    SUMMARY_FILE="${RESULTS_DIR}/timing_summary.log"
    SUMMARY_TXT="${RESULTS_DIR}/summary.txt"
    
    # Create and touch all global log files
    touch "$GLOBAL_LOG"
    touch "$ERROR_LOG"
    touch "$SUMMARY_FILE"
    touch "$SUMMARY_TXT"
    
    # Create tool-specific directories and files for each tool
    for tool in "${TOOLS[@]}"; do
        # Create tool directory and its subdirectories
        mkdir -p "${RESULTS_DIR}/${tool}"
        mkdir -p "${RESULTS_DIR}/${tool}/log"
        
        # Create tool-specific log files
        touch "${RESULTS_DIR}/${tool}/progress.log"
        touch "${RESULTS_DIR}/${tool}/time.txt"
        touch "${RESULTS_DIR}/${tool}/error.log"
        touch "${RESULTS_DIR}/${tool}/summary.log"
    done
    
    # Export log file paths for use in other functions
    export GLOBAL_LOG ERROR_LOG SUMMARY_FILE SUMMARY_TXT
}

# Set up all directories and files
setup_directories

# Set up error handling
log_error() {
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  local message="$1"
  echo "[ERROR] [$timestamp] $message" | tee -a "$ERROR_LOG"
  echo "[ERROR] [$timestamp] $message" >> "$GLOBAL_LOG"
}

log_warning() {
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  local message="$1"
  echo "[WARNING] [$timestamp] $message" | tee -a "$ERROR_LOG"
  echo "[WARNING] [$timestamp] $message" >> "$GLOBAL_LOG"
}

log_info() {
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  local message="$1"
  echo "[INFO] [$timestamp] $message" | tee -a "$GLOBAL_LOG"
}

# Function to run a command with timeout
run_with_timeout() {
    local timeout=$1
    local cmd=$2
    local log_file=$3
    local error_msg=$4
    local success_msg=$5
    
    # Check if docker is available
    if ! check_docker; then
        log_error "Docker or docker-compose not available. Cannot continue."
        return 1
    fi
    
    # Run command with timeout
    if timeout "$timeout" bash -c "$cmd" > >(tee -a "$log_file") 2> >(tee -a "$log_file" >&2); then
        if [ -n "$success_msg" ]; then
            log_info "$success_msg"
        fi
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            log_error "Command timed out after ${timeout} seconds: $cmd"
        else
            log_error "$error_msg (exit code: $exit_code)"
        fi
        return 1
    fi
}

# Function to run a single tool
run_tool() {
    local tool=$1
    local tool_dir="${RESULTS_DIR}/${tool}"
    local tool_log="${tool_dir}/progress.log"
    local tool_time="${tool_dir}/time.txt"
    local tool_error="${tool_dir}/error.log"
    local tool_summary="${tool_dir}/summary.log"
    local log_dir="${tool_dir}/log"
    local tool_parallel=$MAX_PARALLEL
    local total_batches=0
    local successful_batches=0
    local failed_batches=0

    touch tool_log
    
    # Adjust parallel value for codeql
    if [ "$tool" = "codeql" ]; then
        tool_parallel=$((MAX_PARALLEL - 5))
        log_info "Using reduced parallel value of ${tool_parallel} for codeql (original: ${MAX_PARALLEL})"
    fi
    
    log_info "=== Starting analysis with tool: ${tool} ==="
    echo "Tool: ${tool} started at $(date)" > "${tool_log}"
    echo "Using parallel value: ${tool_parallel}" >> "${tool_log}"
    
    # Generate Docker Compose file for this tool
    log_info "Generating Docker Compose for ${tool}..."
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
    if ! go run "${REPO_ROOT}/cmd/compose" -out-dir "$RESULTS_DIR" -verbose -tools "${tool}" "${DATASET}"; then
        log_error "Failed to generate Docker Compose for ${tool}. Continuing with next tool..."
        return 1
    fi
    
    # Check if docker is available
    if ! check_docker; then
        log_error "Docker or docker-compose not available. Skipping tool: ${tool}"
        return 1
    fi
    
    # Get list of services defined in the file
    local service_cmd="docker-compose -f \"$DOCKER_YAML\" config --services"
    if ! SERVICES=$(eval "$service_cmd"); then
        log_error "Failed to get services from docker-compose file. Skipping tool: ${tool}"
        return 1
    fi
    
    TOTAL=$(echo "$SERVICES" | wc -l)
    if [ "$TOTAL" -eq 0 ]; then
        log_warning "No services found for tool: ${tool}. Skipping."
        return 0
    fi
    
    # Convert to array for indexing
    readarray -t SERVICE_ARRAY <<< "$SERVICES"
    
    # Start timing the execution
    start_time=$(date +%s)
    
    for ((i = 0; i < TOTAL; i += tool_parallel)); do
        ((total_batches++))
        local batch_num=$((i/tool_parallel+1))
        local batch_log="${log_dir}/batch_${batch_num}.log"
        local batch_error="${log_dir}/batch_${batch_num}.err"
        
        # Ensure batch log files exist
        touch "$batch_log"
        touch "$batch_error"
        
        log_info "Processing batch ${batch_num} for ${tool}"
        echo "Batch ${batch_num} started at $(date)" >> "${tool_log}"
        
        # Get the current batch
        BATCH=("${SERVICE_ARRAY[@]:i:tool_parallel}")
        
        # Build only services in this batch
        log_info "Building services: ${BATCH[*]}"
        if ! run_with_timeout "$DOCKER_BUILD_TIMEOUT" "docker-compose -f \"$DOCKER_YAML\" build ${BATCH[*]}" "$batch_log" "Failed to build services for batch ${batch_num}"; then
            log_error "Skipping to next batch due to build failure"
            ((failed_batches++))
            continue
        fi
        
        # Start batch in background (detached)
        log_info "Starting services: ${BATCH[*]}"
        if ! run_with_timeout 60 "docker-compose -f \"$DOCKER_YAML\" up -d ${BATCH[*]}" "$batch_log" "Failed to start services for batch ${batch_num}"; then
            log_error "Failed to start services for batch ${batch_num}. Cleaning up and continuing..."
            docker-compose -f "$DOCKER_YAML" down --remove-orphans
            ((failed_batches++))
            continue
        fi
        
        # Check if containers actually started
        sleep 2
        local running_containers
        running_containers=$(docker-compose -f "$DOCKER_YAML" ps -q "${BATCH[@]}" 2>/dev/null | wc -l)
        
        if [ "$running_containers" -eq 0 ]; then
            log_error "No containers are running for batch ${batch_num}. Moving to next batch."
            docker-compose -f "$DOCKER_YAML" down --remove-orphans
            ((failed_batches++))
            continue
        fi
        
        # Wait here with timeout, but continue even if timeout occurs
        log_info "Waiting for batch ${batch_num} to complete (max ${DOCKER_RUN_TIMEOUT}s)..."
        if ! run_with_timeout "$DOCKER_RUN_TIMEOUT" "docker-compose -f \"$DOCKER_YAML\" logs -f --tail=10 ${BATCH[*]}" "$batch_log" "Container execution timed out for batch ${batch_num}"; then
            log_warning "Container execution timed out or failed for batch ${batch_num}. Will still attempt to clean up."
        fi
        
        # Verify containers are still running and check for memory issues
        for service in "${BATCH[@]}"; do
            local container_id
            container_id=$(docker-compose -f "$DOCKER_YAML" ps -q "$service" 2>/dev/null)
            
            if [ -z "$container_id" ]; then
                log_warning "Container for service $service is not running."
                continue
            fi
            
            # Check container status for OOM or other issues
            local container_status
            container_status=$(docker inspect --format='{{.State.Status}}' "$container_id" 2>/dev/null)
            
            if [ "$container_status" != "running" ]; then
                local container_exit_code
                container_exit_code=$(docker inspect --format='{{.State.ExitCode}}' "$container_id" 2>/dev/null)
                local container_oom
                container_oom=$(docker inspect --format='{{.State.OOMKilled}}' "$container_id" 2>/dev/null)
                
                if [ "$container_oom" = "true" ]; then
                    log_error "Container for service $service was killed due to out of memory"
                else
                    log_error "Container for service $service exited with code $container_exit_code"
                fi
            fi
        done
        
        # Clean up containers
        log_info "Cleaning up batch ${batch_num}..."
        if ! run_with_timeout 60 "docker-compose -f \"$DOCKER_YAML\" down --remove-orphans" "$batch_log" "Failed to clean up containers for batch ${batch_num}"; then
            log_warning "Failed to clean up containers for batch ${batch_num}. Continuing anyway."
            # Force cleanup if needed
            docker ps -a | grep "$tool" | awk '{print $1}' | xargs -r docker rm -f
        fi
        
        # Log progress after each batch
        log_info "Batch ${batch_num} completed at $(date)"
        echo "Batch ${batch_num} completed at $(date)" >> "${tool_log}"
        ((successful_batches++))
    done
    
    # End timing the execution
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    log_info "=== Completed analysis with tool: ${tool} ==="
    log_info "Total batches: $total_batches, Successful: $successful_batches, Failed: $failed_batches"
    echo "Total execution time for ${tool}: ${duration} seconds" > "${tool_time}"
    echo "Tool: ${tool} completed at $(date)" >> "${tool_log}"
    echo "Statistics - Total batches: $total_batches, Successful: $successful_batches, Failed: $failed_batches" >> "${tool_log}"
}

# Initial check for docker availability
if ! check_docker; then
    log_error "Docker or docker-compose not available. Cannot continue."
    exit 1
fi

# Run each tool sequentially
total_tools=${#TOOLS[@]}
successful_tools=0
failed_tools=0

log_info "Starting analysis with ${total_tools} tool(s): ${TOOLS[*]}"

for tool in "${TOOLS[@]}"; do
    if run_tool "${tool}"; then
        ((successful_tools++))
    else
        log_warning "Tool $tool did not complete successfully"
        ((failed_tools++))
    fi
done

# Create a summary of all tools
log_info "=== Analysis Summary ==="
echo "=== Analysis Summary ===" > "results_${TIMESTAMP}/summary.txt"
echo "Total tools: $total_tools, Successful: $successful_tools, Failed: $failed_tools" >> "results_${TIMESTAMP}/summary.txt"

for tool in "${TOOLS[@]}"; do
    if [ -f "results_${TIMESTAMP}/${tool}_time.txt" ]; then
        echo "${tool}: $(cat results_${TIMESTAMP}/${tool}_time.txt)" >> "results_${TIMESTAMP}/summary.txt"
    else
        echo "${tool}: Failed or No timing information available" >> "results_${TIMESTAMP}/summary.txt"
    fi
done

log_info "Analysis completed. Tools: $total_tools, Successful: $successful_tools, Failed: $failed_tools"
log_info "Results are in $RESULTS_DIR"
echo "All tools completed. Results are in results_${TIMESTAMP}/"
