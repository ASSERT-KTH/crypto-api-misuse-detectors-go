#!/bin/bash

# Script for running tool analysis with batch scheduling to reduce network overhead

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
TIMESTAMP=$(date +%Y%m%d_%H%M)
mkdir -p "results_${TIMESTAMP}"
RESULTS_DIR="results_${TIMESTAMP}"
PROJECT_NAME="cryptoapi_${TIMESTAMP}"  # Unique project name for this run

# global log files
GLOBAL_LOG="${RESULTS_DIR}/global.log"
SUMMARY_FILE="${RESULTS_DIR}/timing_summary.log"
touch "$GLOBAL_LOG"
touch "$SUMMARY_FILE"

# Export for parallel environment
export RESULTS_DIR DOCKER_YAML MAX_PARALLEL DATASET GLOBAL_LOG SUMMARY_FILE PROJECT_NAME

echo "=== Starting tool analysis at $(date) ===" | tee -a "$GLOBAL_LOG"
echo "Configuration:" | tee -a "$GLOBAL_LOG"
echo "- Dataset: $DATASET" | tee -a "$GLOBAL_LOG"
echo "- Docker Compose: $DOCKER_YAML" | tee -a "$GLOBAL_LOG"
echo "- Maximum parallel jobs: $MAX_PARALLEL" | tee -a "$GLOBAL_LOG"
echo "- Tools to run: ${TOOLS[*]}" | tee -a "$GLOBAL_LOG"
echo "- Results directory: $RESULTS_DIR" | tee -a "$GLOBAL_LOG"
echo "- Project name: $PROJECT_NAME" | tee -a "$GLOBAL_LOG"
echo "- batch size: $batch_size services per batch" | tee -a "$GLOBAL_LOG"
echo "- Container timeout: 30 minutes" | tee -a "$GLOBAL_LOG"
echo "- Batch monitoring timeout: 30 minutes" | tee -a "$GLOBAL_LOG"
echo "----------------------------------------" | tee -a "$GLOBAL_LOG"

# Function to run a batch of services with a single docker-compose command
run_batch() {
    local tool=$1
    local batch_number=$2
    local services=$3
    local tool_dir="${RESULTS_DIR}/${tool}"
    local summary_log="${tool_dir}/summary.log"
    local batch_error="${tool_dir}/batch_${batch_number}.err"
    local batch_output="${tool_dir}/batch_${batch_number}.out"
    local project_name="${PROJECT_NAME}_${tool}_batch${batch_number}"
    
    mkdir -p "$tool_dir"
    
    echo "[$(date +%H:%M:%S)] Starting ${tool} analysis batch ${batch_number} with services: ${services}" | tee -a "$GLOBAL_LOG" "$summary_log"
    
    # Build services in this batch
    if docker-compose -f "$DOCKER_YAML" --project-name "$project_name" build $services 2> >(tee -a "${batch_error}" >&2) | tee -a "${batch_output}"; then
        # Track start time
        start_time=$(date +%s)
        
        # Run the services directly (not detached) with timeout and resource limits
        # Using tee to capture output while still showing it
        if timeout 30m docker-compose -f "$DOCKER_YAML" --project-name "$project_name" up --no-deps $services 2> >(tee -a "${batch_error}" >&2) | tee -a "${batch_output}"; then
            status="OK"
        else
            exit_code=$?
            if [ $exit_code -eq 124 ]; then
                status="TIMEOUT"
                echo "[$(date +%H:%M:%S)] Batch ${batch_number} timed out after 30 minutes" | tee -a "$summary_log"
                docker-compose -f "$DOCKER_YAML" --project-name "$project_name" stop 2> >(tee -a "${batch_error}" >&2) | tee -a "${batch_output}"
            elif [ $exit_code -eq 137 ]; then
                status="OOM"
                echo "[$(date +%H:%M:%S)] Batch ${batch_number} was killed due to out of memory" | tee -a "$summary_log"
            else
                status="ERROR"
                echo "[$(date +%H:%M:%S)] Batch ${batch_number} failed with exit code ${exit_code}" | tee -a "$summary_log"
            fi
        fi
        
        # Track end time and calculate duration
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        
        # Log container resource usage if available
        for service in $services; do
            container_name="${project_name}_${service}_1"
            if docker stats --no-stream "$container_name" 2>/dev/null | tee -a "${batch_output}"; then
                #echo "Resource usage for ${service}:" | tee -a "$summary_log" "${batch_output}"
                docker stats --no-stream "$container_name" | tee -a "$summary_log" "${batch_output}"
            fi
        done
        
        # Clean up all containers and network at once, regardless of status
        if ! docker-compose -f "$DOCKER_YAML" --project-name "$project_name" down --volumes --remove-orphans 2> >(tee -a "${batch_error}" >&2) | tee -a "${batch_output}"; then
            echo "[$(date +%H:%M:%S)] Warning: Error during cleanup" | tee -a "$summary_log" "${batch_output}"
        fi
        
        echo "[$(date +%H:%M:%S)] Completed ${tool} batch ${batch_number} - Status: ${status}, Duration: ${duration}s" | tee -a "$GLOBAL_LOG" "$summary_log"
        
        # Record batch completion with more detailed status
        echo "[$(date +%H:%M:%S)] Batch ${batch_number} completed with status: ${status}" | tee -a "$summary_log"
        if [ "$status" != "SUCCESS" ]; then
            echo "[$(date +%H:%M:%S)] Batch ${batch_number} error details can be found in: ${batch_error}" | tee -a "$summary_log"
            echo "[$(date +%H:%M:%S)] Batch ${batch_number} output can be found in: ${batch_output}" | tee -a "$summary_log"
        fi
        
        return 0
    else
        # Clean up on failure
        docker-compose -f "$DOCKER_YAML" --project-name "$project_name" down --volumes --remove-orphans >> /dev/null 2>> "${batch_error}"
        echo "[$(date +%H:%M:%S)] Failed to build ${tool} batch ${batch_number}" | tee -a "$GLOBAL_LOG" "$summary_log"
        return 1
    fi
}
export -f run_batch

# Function to run a tool with batched services
run_tool() {
    local tool=$1
    local tool_log="${RESULTS_DIR}/${tool}/progress.log"
    local tool_error="${RESULTS_DIR}/${tool}/error.log"
    local tool_time="${RESULTS_DIR}/${tool}/time.txt"
    local summary_log="${RESULTS_DIR}/${tool}/summary.log"
    local tool_parallel=$MAX_PARALLEL
    local batch_size=3
    
    mkdir -p "${RESULTS_DIR}/${tool}"
    touch "$summary_log"  # Create summary log file
    
    # Adjust parallelism for resource-intensive tools
    if [ "$tool" = "codeql" ]; then
        batch_size=2  # CodeQL is resource intensive, reduce batch size
        echo "[$(date +%H:%M:%S)] Tool configuration for ${tool}:" | tee -a "$GLOBAL_LOG" "$tool_log"
        echo "- Using reduced parallel value: ${tool_parallel} (adjusted from ${MAX_PARALLEL})" | tee -a "$GLOBAL_LOG" "$tool_log"
        echo "- Batch size: ${batch_size} services per batch (reduced due to resource intensity)" | tee -a "$GLOBAL_LOG" "$tool_log"
    else
        echo "[$(date +%H:%M:%S)] Tool configuration for ${tool}:" | tee -a "$GLOBAL_LOG" "$tool_log"
        echo "- Parallel jobs: ${tool_parallel}" | tee -a "$GLOBAL_LOG" "$tool_log"
        echo "- Batch size: ${batch_size} services per batch" | tee -a "$GLOBAL_LOG" "$tool_log"
    fi
    
    echo "[$(date +%H:%M:%S)] === Starting analysis with tool: ${tool} ===" | tee -a "$GLOBAL_LOG" "$tool_log"
    
    # Generate Docker Compose file for this tool
    echo "[$(date +%H:%M:%S)] Generating Docker Compose for ${tool}..." | tee -a "$GLOBAL_LOG" "$tool_log"
    if ! go run ./cmd/compose -out-dir "$RESULTS_DIR" -verbose -tools "${tool}" "${DATASET}" 2> >(tee -a "$tool_error" >&2) | tee -a "$tool_log"; then
        echo "[$(date +%H:%M:%S)] Failed to generate Docker Compose for ${tool}. Exiting..." | tee -a "$GLOBAL_LOG" "$tool_error"
        return 1
    fi
    
    # Get list of services defined in the file
    SERVICES=$(docker-compose -f "$DOCKER_YAML" config --services)
    TOTAL=$(echo "$SERVICES" | wc -l)
    
    echo "[$(date +%H:%M:%S)] Found ${TOTAL} services to analyze with ${tool}" | tee -a "$GLOBAL_LOG" "$tool_log"
    
    # Start timing the execution
    start_time=$(date +%s)
    
    # Create batches of services and run them in parallel
    batch_number=0
    batch_commands=()
    current_batch=""
    count=0
    
    # Create batch commands
    for service in $SERVICES; do
        if [ $count -eq 0 ]; then
            current_batch="$service"
        else
            current_batch="$current_batch $service"
        fi
        
        count=$((count + 1))
        
        # When batch is full or we've reached the last service, add to commands list
        if [ $count -eq $batch_size ] || [ "$service" = "$(echo "$SERVICES" | tail -n 1)" ]; then
            batch_commands+=("run_batch $tool $batch_number \"$current_batch\"")
            batch_number=$((batch_number + 1))
            current_batch=""
            count=0
        fi
    done
    
    # Run batches in parallel
    printf "%s\n" "${batch_commands[@]}" | parallel --will-cite -j "$tool_parallel" bash -c '{}'
    
    # End timing
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    echo "Total execution time for ${tool}: ${duration} seconds" | tee -a "$tool_time" "$GLOBAL_LOG"
    echo "[$(date +%H:%M:%S)] === Completed analysis with tool: ${tool} ===" | tee -a "$GLOBAL_LOG" "$tool_log"
    
    # Summary
    echo "[$(date +%H:%M:%S)] ${tool}: ${duration} seconds (${TOTAL} services in ${batch_number} batches)" >> "$SUMMARY_FILE"
    echo "----------------------------------------" >> "$summary_log"
    echo "Tool Summary:" >> "$summary_log"
    echo "- Total services: ${TOTAL}" >> "$summary_log"
    echo "- Total batches: ${batch_number}" >> "$summary_log"
    echo "- Total duration: ${duration} seconds" >> "$summary_log"
    echo "----------------------------------------" >> "$summary_log"
    
    return 0
}

# Run each tool sequentially with parallel execution of batches within each tool
for tool in "${TOOLS[@]}"; do
    run_tool "${tool}"
    # Run cleanup script between tools
    echo "Running cleanup between tools..."
    ./scripts/cleanup.sh
    echo "Cleanup completed, proceeding to next tool..."
done

echo "[$(date +%H:%M:%S)] All tools completed. Results are in ${RESULTS_DIR}/" | tee -a "$GLOBAL_LOG"
echo "=== Timing Summary ===" | tee -a "$GLOBAL_LOG" "$SUMMARY_FILE"
tee -a "$GLOBAL_LOG" < "$SUMMARY_FILE"
