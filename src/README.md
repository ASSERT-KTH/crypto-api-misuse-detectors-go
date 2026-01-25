# Tool Consensus Analysis

Analyzes security tool findings (CodeQL, Gosec, Gopher, Snyk) and generates consensus metrics.

## Run

```bash
uv run analyze-results raw_results --output-dir ./analysis_output
```

## Input Structure

```
raw_results/
├── project1/
│   ├── codeql/CWE-*.csv
│   ├── gosec/results.json
│   ├── gopher/results.json
│   └── snyk/results.json
└── project2/...
```
