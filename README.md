# Go CryptoAPI

A tool for analyzing cryptographic API misuse vulnerabilities in Go projects.

## Commands

### vulnrunner

Generates Docker compose configurations and runs vulnerability analysis on specified repositories.

```bash
# Generate compose file and optionally run containers
go run ./cmd/vulnrunner -file <vulnerability_json_file> [-up]
```

Options:
- `-file`: Path to vulnerability JSON file (required)
- `-up`: Run docker compose after generating the configuration (optional)

The tool:
1. Generates a Docker compose configuration based on vulnerability information
2. Creates metadata files with vulnerability details
3. Sets up containers to run Gopher analysis
4. Stores results in `data/analysis/cve/<dataset_name>/<repo-id>`

### gopher
A binary to run crypto API misuse analysis (static).
>Ref: [https://github.com/yxzhang2024/gopher](https://github.com/yxzhang2024/gopher)

## Project Structure

- `cmd/vulnrunner`: Main command for vulnerability analysis setup and execution
- `internal/docker`: Docker compose generation and container management
- `data/`: Vulnerability datasets and analysis results


## modcollector

gets popular repos and downloads them locally.



