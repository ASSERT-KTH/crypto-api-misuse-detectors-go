#!/usr/bin/env python3
"""
Analyze security tool findings and generate visualizations.

This script processes analysis results from multiple security tools (CodeQL, Gosec, Gopher, Snyk)
and generates:
1. Venn diagrams showing tool overlaps
2. Rule-level analysis of findings
3. Metrics and statistics about tool performance

Usage:
    python3 main.py <results_directory> [--output-dir OUTPUT_DIR] [--analysis-type {venn,rules,all}]

Example:
    python3 main.py ../results_20250518 --analysis-type all
    python3 main.py ../results_20250518 --analysis-type venn --output-dir ./analysis_output
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Dict, Any, List, TypedDict, Literal

from batch.collector import FindingsCollector
from batch.venn_analyzer import VennMetricsAnalyzer
from batch.metrics_visualizer import MetricsVisualizer
from batch.rule_analyzer import RuleMetricsAnalyzer
from config import (
    ToolName,
    DEFAULT_TOOLS,
    DEFAULT_SAMPLING_PATTERNS,
    MAX_SAMPLES_PER_PATTERN,
    OUTPUT_FILES,
)


class LocationMap(TypedDict):
    codeql: List[Dict[str, Any]]
    gosec: List[Dict[str, Any]]
    gopher: List[Dict[str, Any]]
    snyk: List[Dict[str, Any]]


class ProjectFindings(TypedDict):
    location_map: LocationMap


class FindingsData(TypedDict):
    project_findings: Dict[str, ProjectFindings]


AnalysisType = Literal["venn", "rules", "all"]


def print_project_summary(project_findings: Dict[str, ProjectFindings]) -> None:
    """Print summary of findings per project."""
    print(f"\nFound {len(project_findings)} projects:")
    for project_name, findings in project_findings.items():
        location_map = findings.get("location_map", {})
        total_findings = sum(
            len(tool_findings) for tool_findings in location_map.values()
        )
        print(f"  {project_name}: {total_findings} total findings")


def print_analysis_summary(output_path: Path, analysis_type: str) -> None:
    """Print summary of generated analysis outputs."""
    print(f"\n✓ {analysis_type.title()} analysis completed successfully!")
    print(f"  Output location: {output_path}")
    print(f"  Generated files:")

    if analysis_type == "venn":
        print(f"    - {OUTPUT_FILES['venn_diagram']} (overall tool overlaps)")
        # List rule-specific diagrams
        rule_files = list(output_path.glob("rule_*_venn.png"))
        if rule_files:
            print(f"    - {len(rule_files)} rule-specific diagrams")
            for rule_file in sorted(rule_files)[:3]:
                print(f"      * {rule_file.name}")
            if len(rule_files) > 3:
                print(f"      * ... and {len(rule_files) - 3} more")

        print(f"    - {OUTPUT_FILES['metrics_summary']} (detailed metrics data)")
        print(
            f"    - {OUTPUT_FILES['sampling_data']} (tool agreement/disagreement data)"
        )
        print(
            f"    - {OUTPUT_FILES['location_samples']} (sampled locations for assessment)"
        )

    elif analysis_type == "rules":
        print(f"    - {OUTPUT_FILES['rule_metrics']} (basic rule metrics)")
        print(f"    - {OUTPUT_FILES['rule_findings']} (detailed findings analysis)")
        print(f"    - {OUTPUT_FILES['rule_samples']} (sampled findings for assessment)")


def run_venn_analysis(
    findings_data: FindingsData,
    output_path: Path,
    tools: List[ToolName] = DEFAULT_TOOLS,
    sampling_patterns: List[str] = DEFAULT_SAMPLING_PATTERNS,
) -> None:
    """Run Venn diagram analysis and generate visualizations.

    Args:
        findings_data: The collected findings data
        output_path: Directory to write output files
        tools: List of tools to include in analysis
        sampling_patterns: List of tool agreement patterns to sample
    """
    print("\n>> Calculating metrics...")
    analyzer = VennMetricsAnalyzer(findings_data)
    metrics = analyzer.analyze_metrics()

    print("\n>> Generating Venn diagrams...")
    visualizer = MetricsVisualizer(metrics, tools=tools)
    venn_output = output_path / "venn_diagrams"
    venn_output.mkdir(parents=True, exist_ok=True)

    # Generate diagrams and metrics
    visualizer.generate_venn_diagrams(venn_output)
    visualizer.generate_metrics_summary(venn_output / OUTPUT_FILES["metrics_summary"])

    # Write sampling data
    print("\n>> Writing sampling data...")
    sampling_output = venn_output / OUTPUT_FILES["sampling_data"]
    with open(sampling_output, "w") as f:
        json.dump(metrics["sampling_data"], f, indent=2)

    # Generate location samples
    print("\n>> Generating location samples...")
    samples = analyzer.sample_agreement_patterns(
        max_samples_per_pattern=MAX_SAMPLES_PER_PATTERN,
        output_file=venn_output / OUTPUT_FILES["location_samples"],
        include_patterns=sampling_patterns,
    )
    analyzer.print_sampling_summary(samples)
    print_analysis_summary(venn_output, "venn")


def run_rule_analysis(collector: FindingsCollector, output_path: Path) -> None:
    """Run rule-level analysis of findings."""
    print("\n>> Analyzing rule-level metrics...")
    rule_output = output_path / "rule_analysis"
    rule_output.mkdir(parents=True, exist_ok=True)

    # Initialize analyzer and process findings
    rule_analyzer = RuleMetricsAnalyzer(collector.all_detections_per_rule)
    rule_metrics = rule_analyzer.analyze_rule_metrics()

    # Save metrics and summaries
    with open(rule_output / OUTPUT_FILES["rule_metrics"], "w") as f:
        json.dump(rule_metrics, f, indent=2)

    rule_analyzer.print_all_findings_summary(
        output_file=rule_output / OUTPUT_FILES["rule_findings"]
    )

    # Generate samples
    samples = rule_analyzer.sample_findings_for_assessment(
        output_file=rule_output / OUTPUT_FILES["rule_samples"]
    )

    # Print summaries
    rule_analyzer.print_rule_metrics(rule_metrics)
    rule_analyzer.print_sampling_summary(samples)
    print_analysis_summary(rule_output, "rules")


def main() -> None:
    """Main entry point for the analysis script."""
    parser = argparse.ArgumentParser(
        description="Analyze and visualize security tool findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "results_dir", help="Path to directory containing tool analysis results"
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for analysis output (default: <results_dir>/analysis_output)",
    )
    parser.add_argument(
        "--analysis-type",
        choices=["venn", "rules", "all"],
        default="all",
        help="Type of analysis to perform",
        type=lambda x: x.lower() if isinstance(x, str) else x,
    )
    args = parser.parse_args()

    try:
        # Setup paths
        results_path = Path(args.results_dir)
        if not results_path.exists():
            raise FileNotFoundError(f"Results directory not found: {args.results_dir}")

        output_path = (
            Path(args.output_dir)
            if args.output_dir
            else results_path / "analysis_output"
        )
        output_path.mkdir(parents=True, exist_ok=True)

        # Collect findings
        print("\n>> Collecting findings from all projects...")
        collector = FindingsCollector(results_path)
        findings_data = collector.collect_all_findings()
        print_project_summary(findings_data["project_findings"])

        # Run requested analyses
        if args.analysis_type in ["venn", "all"]:
            run_venn_analysis(findings_data, output_path)

        if args.analysis_type in ["rules", "all"]:
            run_rule_analysis(collector, output_path)

    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("\nTip: Make sure the results directory path is correct")
        sys.exit(1)
    except ImportError as e:
        print(f"Import Error: {e}")
        print(
            "\nTip: Make sure you're in the analyzer directory and the virtual environment is activated:"
        )
        print("  cd /path/to/analyzer")
        print("  source .venv/bin/activate")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        print("\nFor debugging, try running with Python's verbose flag:")
        print(f"  python3 -v main.py {args.results_dir}")
        sys.exit(1)


if __name__ == "__main__":
    main()
