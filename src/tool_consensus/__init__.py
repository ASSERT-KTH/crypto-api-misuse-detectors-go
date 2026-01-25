"""
Security Tool Findings Analyzer

This package provides tools for analyzing and comparing findings from multiple
security tools (CodeQL, Gosec, and Gopher) across multiple projects. It includes
functionality for:
- Analyzing individual projects
- Batch analysis across multiple projects
- Generating Venn diagrams for tool overlap
- Calculating metrics and consensus data
"""

from .analyze import Analyzer
from .venn_utils import calculate_venn_regions, validate_venn_calculations
from .batch import (
    FindingsCollector,
    VennMetricsAnalyzer,
    VennDiagramGenerator,
)

__all__ = [
    "Analyzer",
    "calculate_venn_regions",
    "validate_venn_calculations",
    "FindingsCollector",
    "VennMetricsAnalyzer",
    "VennDiagramGenerator",
]
