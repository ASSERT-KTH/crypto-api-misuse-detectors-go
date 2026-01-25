#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}/internal/docker"
echo "Cleaning up Docker containers and images..."
docker compose down --remove-orphans
# Remove all containers and images related to cryptoap
echo "Removing all cryptoapi images..."
docker images --format '{{.Repository}}:{{.Tag}}' | grep '^cryptoapi' | xargs -r docker rmi -f || true
echo "Stopping and removing all cryptoapi containers..."
docker stop $(docker ps -a --filter "name=github.com-" --format "{{.ID}}") || true
docker rm $(docker ps -a --filter "name=github.com-" --format "{{.ID}}") || true
echo "Removing all cryptoapi networks..."
docker network rm $(docker network ls --filter "name=^crypto" --format "{{.Name}}") || true
