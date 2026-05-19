# Crypto API Misuse Detectors for Go - Replication Package

This repository contains the complete replication package for [a comparative study of static analysis tools detecting cryptographic API misuse in Go projects](http://oadoi.org/10.1145/3786165.3788440).

```bibtex
@inproceedings{10.1145-3786165.3788440,
 title = {Evaluating Cryptographic API Misuse Detectors for Go},
 year = {2026},
 doi = {10.1145/3786165.3788440},
 author = {Vivi Andersson and Martin Monperrus},
 url = {http://oadoi.org/10.1145/3786165.3788440},
 booktitle = {Proceedings of the 2026 IEEE/ACM 4th International Workshop on Software Vulnerability Management},
}
```

**Tools compared:** CodeQL, Gosec, Gopher, Snyk

**Dataset:** 329 open-source Go projects analyzed for crypto API misuse patterns

**Included in this package:**
- 📊 Complete analysis results (`results/` directory)
  - 14 rule-specific Venn diagrams + overall tool consensus
  - Rule-level metrics and sampling data
- 🔬 Raw tool outputs (`raw_results/` - 206MB, 329 projects)
- 🐍 Python analysis code (`src/tool_consensus/`)
- 🐳 Docker composition tooling for running experiments
- 📝 Experiment orchestration scripts

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

Analyze tool consensus and generate Venn diagrams from results.

**Setup:**
```bash
pip install -r src/requirements.txt
```

**Run:**
```bash
uv run analyze-results raw_results --output-dir ./analysis_output
```

**Output:** Venn diagrams, metrics, and sampled findings in `analysis_output/`

## Pre-computed Results

Analysis results are already included in the `results/` directory:
- `venn_diagrams/` - Visual tool overlap analysis
- `rule_analysis/` - Per-rule metrics and findings

## Repository Structure

```
.
├── cmd/              # Compose file generator
├── data/             # Dataset metadata
├── internal/         # Tool configurations and Docker setup
├── scripts/          # Experiment orchestration
├── src/              # Python analysis code
├── raw_results/      # Tool outputs (329 projects)
└── results/          # Pre-computed analysis
```

## License

MIT License - See LICENSE file for details
