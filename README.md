# Go CryptoAPI Analysis

Replication package for Go cryptographic API tool analysis study.

## Composer

Generate Docker Compose files for running experiments.

**Setup:**
- [Install Go](https://go.dev/doc/install) and run `go mod download`
- Add to `internal/docker/.env`: `BASE_DIR=/absolute/path/to/go-cryptoapi`

**Usage:**
```bash
go run cmd/compose/main.go -tools <toolname> -verbose <datasetpath>
```

## Experiments

**Setup tools:**
- CodeQL: Clone into `internal/tool/codeql-home` ([instructions](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/advanced-setup-of-the-codeql-cli))
- Snyk: Download binary to `internal/tool/snyk` ([instructions](https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli)) and add `SNYK_TOKEN=` to `internal/docker/.env`
- Gopher/Gosec: Included

**Run:**
```bash
./run_experiments_batches.sh <dataset> <compose_dir> <batch_size> <parallel_batches> <tools>
```

## Analysis

**Setup:**
```bash
pip install -r src/requirements.txt
```

**Run:**
```bash
uv run analyze-results raw_results --output-dir ./analysis_output
```