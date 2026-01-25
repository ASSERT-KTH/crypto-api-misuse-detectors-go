"""Configuration settings for analyzing consensus etc. 

This module contains configuration settings for:
- Available security tools
- Default tool combinations
- Sampling patterns for analysis
"""

from typing import List, Literal

# Available security tools
ToolName = Literal["codeql", "gosec", "gopher", "snyk"]

# Default tools to use in analysis
DEFAULT_TOOLS: List[ToolName] = ["codeql", "gosec", "gopher", "snyk"]

# Default sampling patterns for Venn analysis
# These patterns represent different combinations of tool agreements
DEFAULT_SAMPLING_PATTERNS = [
    # Single tool findings
    "codeql_only",
    "gosec_only",
    "gopher_only",
    "snyk_only",
    # Two tool agreements
    "codeql_gosec",
    "codeql_gopher",
    "codeql_snyk",
    "gosec_gopher",
    "gosec_snyk",
    "gopher_snyk",
    # Three tool agreements
    "codeql_gosec_gopher",
    "codeql_gosec_snyk",
    "codeql_gopher_snyk",
    "gosec_gopher_snyk",
    # All tools agreement
    "all_tools",
]

# Maximum number of samples to extract from each pattern in the Venn overlap analysis
MAX_SAMPLES_PER_PATTERN = 5

# Output file names
OUTPUT_FILES = {
    "metrics_summary": "metrics_summary.json",
    "sampling_data": "sampling_data.json",
    "location_samples": "location_samples.json",
    "rule_metrics": "rule_metrics.json",
    "rule_findings": "rule_findings_summary.json",
    "rule_samples": "rule_samples.json",
    "venn_diagram": "overall_venn.png",
}
