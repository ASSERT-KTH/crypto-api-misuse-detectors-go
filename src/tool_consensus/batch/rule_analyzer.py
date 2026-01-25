#!/usr/bin/env python3
"""
Rule Metrics Analyzer

This module analyzes findings at the rule level, including:
1. Tool detection counts per rule
2. Random sampling of findings for manual assessment
"""

import random
from typing import Dict, List, Set
from pathlib import Path
import json
from core.findings import Finding


class RuleMetricsAnalyzer:
    """Analyzes findings at the rule level."""

    def __init__(self, all_detections_per_rule: Dict[str, List[Finding]]):
        """Initialize with rule-based findings.

        Args:
            all_detections_per_rule: Dictionary mapping rule IDs to lists of findings
        """
        self.all_detections_per_rule = all_detections_per_rule
        self.tools = ["codeql", "gosec", "gopher", "snyk"]

    def analyze_rule_metrics(self) -> Dict:
        """Analyze metrics for each rule.

        Returns:
            Dict containing:
                - tool_detections: Count of detections per tool for each rule
                - total_detections: Total number of detections per rule
                - implementing_tools: Set of tools that detected each rule
        """
        metrics = {}

        for rule_id, findings in self.all_detections_per_rule.items():
            # Count detections per tool
            tool_counts = {tool: 0 for tool in self.tools}
            implementing_tools = set()

            for finding in findings:
                tool_counts[finding.tool] += 1
                implementing_tools.add(finding.tool)

            metrics[rule_id] = {
                "tool_detections": tool_counts,
                "total_detections": len(findings),
                "implementing_tools": list(implementing_tools),
            }

        return metrics

    def sample_findings_for_assessment(
        self, max_samples_per_rule: int = 16, output_file: Path = None
    ) -> Dict:
        """Sample findings for manual assessment using stratified sampling with minimum tool coverage.

        For each rule:
        1. Ensures at least 3 samples from each tool that reports the rule
        2. Distributes remaining samples proportionally across tools
        3. Maximum total samples per rule is 12 by default

        Args:
            max_samples_per_rule: Maximum number of samples to take per rule (default: 12)
            output_file: Optional path to save samples to JSON

        Returns:
            Dict containing sampled findings per rule and tool
        """
        samples = {}

        for rule_id, findings in self.all_detections_per_rule.items():
            samples[rule_id] = {}

            # Group findings by tool and count
            tool_findings = {tool: [] for tool in self.tools}
            tool_counts = {tool: 0 for tool in self.tools}

            for finding in findings:
                tool_findings[finding.tool].append(finding)
                tool_counts[finding.tool] += 1

            # Calculate total findings for this rule
            total_findings = sum(tool_counts.values())
            if total_findings == 0:
                continue

            # First pass: Allocate minimum 3 samples to each tool that has findings
            tool_samples = {tool: 0 for tool in self.tools}
            remaining_samples = max_samples_per_rule

            # Allocate minimum samples to each tool that has findings
            for tool in self.tools:
                if tool_counts[tool] > 0:
                    min_samples = min(
                        3, tool_counts[tool]
                    )  # Take min of 3 or available findings
                    tool_samples[tool] = min_samples
                    remaining_samples -= min_samples

            # If we've used all samples in minimum allocation, skip proportional distribution
            if remaining_samples <= 0:
                # Adjust if we went over max_samples_per_rule
                if sum(tool_samples.values()) > max_samples_per_rule:
                    excess = sum(tool_samples.values()) - max_samples_per_rule
                    # Reduce samples from tools that have more than minimum
                    for tool in sorted(
                        tool_samples.keys(), key=lambda t: tool_samples[t], reverse=True
                    ):
                        if tool_samples[tool] > 3 and excess > 0:
                            reduction = min(excess, tool_samples[tool] - 3)
                            tool_samples[tool] -= reduction
                            excess -= reduction
            else:
                # Second pass: Distribute remaining samples proportionally
                active_tools = [t for t in self.tools if tool_counts[t] > 0]
                if active_tools:
                    # Calculate proportional distribution of remaining samples
                    total_remaining_findings = sum(tool_counts[t] for t in active_tools)
                    for tool in active_tools:
                        proportion = tool_counts[tool] / total_remaining_findings
                        additional_samples = int(remaining_samples * proportion)
                        # Ensure we don't exceed available findings
                        max_possible = tool_counts[tool] - tool_samples[tool]
                        additional_samples = min(additional_samples, max_possible)
                        tool_samples[tool] += additional_samples
                        remaining_samples -= additional_samples

                    # Distribute any remaining samples to tools with most findings
                    if remaining_samples > 0:
                        sorted_tools = sorted(
                            active_tools, key=lambda t: tool_counts[t], reverse=True
                        )
                        for i in range(remaining_samples):
                            tool = sorted_tools[i % len(sorted_tools)]
                            if tool_samples[tool] < tool_counts[tool]:
                                tool_samples[tool] += 1

            # Sample from each tool according to calculated proportions
            for tool, n_samples in tool_samples.items():
                if n_samples > 0 and tool_findings[tool]:
                    sampled = random.sample(tool_findings[tool], n_samples)
                    samples[rule_id][tool] = [
                        {
                            "file": f.file_path,
                            "project_dir": f.project_dir,
                            "line": f.line,
                            "column": f.column,
                            "message": f.message,
                            "tool": f.tool,
                            "rule_id": f.rule_id,
                            "canonical_ids": f.canonical_ids,
                            "total_findings_for_tool": tool_counts[tool],
                            "total_findings_for_rule": total_findings,
                            "requested_samples": tool_samples[tool],
                            "actual_samples": n_samples,
                        }
                        for f in sampled
                    ]

        # Save to file if requested
        if output_file:
            with open(output_file, "w") as f:
                json.dump(samples, f, indent=2)

        return samples

    def print_sampling_summary(self, samples: Dict) -> None:
        """Print summary of sampling results.

        Args:
            samples: Dictionary of sampled findings
        """
        print("\nSampling Summary:")
        print("=" * 80)

        for rule_id, tool_samples in sorted(samples.items()):
            total_samples = sum(len(fs) for fs in tool_samples.values())
            if total_samples == 0:
                continue

            print(f"\n{rule_id}:")
            print(f"  Total Samples: {total_samples}")
            print("  Samples per Tool:")
            for tool, findings in tool_samples.items():
                if findings:
                    print(f"    - {tool}: {len(findings)} samples")
                    # Print context from first finding
                    f = findings[0]
                    print(f"      (from {f['total_findings_for_tool']} total findings)")
            print(
                f"  Total Findings for Rule: {findings[0]['total_findings_for_rule']}"
            )

    def print_rule_metrics(
        self, metrics: Dict = None, output_file: Path = None
    ) -> None:
        """Print summary of rule metrics.

        Args:
            metrics: Optional pre-calculated metrics. If None, will use generate_findings_summary
            output_file: Optional path to save metrics to JSON
        """
        if metrics is None:
            # Use the more detailed summary but only print the basic metrics
            summary = self.generate_findings_summary()
            metrics = {
                rule_id: {
                    "total_detections": data["total_findings"],
                    "implementing_tools": list(data["tool_statistics"].keys()),
                    "tool_detections": {
                        tool: stats["total_findings"]
                        for tool, stats in data["tool_statistics"].items()
                    },
                }
                for rule_id, data in summary.items()
            }

        print("\nRule Metrics Summary:")
        print("=" * 80)

        for rule_id, data in sorted(metrics.items()):
            print(f"\n{rule_id}:")
            print(f"  Total Detections: {data['total_detections']}")
            print(
                f"  Implementing Tools: {', '.join(sorted(data['implementing_tools']))}"
            )
            print("  Tool Detections:")
            for tool, count in data["tool_detections"].items():
                if count > 0:
                    print(f"    - {tool}: {count}")

        # Save to file if requested
        if output_file:
            with open(output_file, "w") as f:
                json.dump(metrics, f, indent=2)

    def print_all_findings_summary(self, output_file: Path = None) -> None:
        """Print and optionally save detailed summary of all findings across rules and tools.

        This is a more detailed version of print_rule_metrics that includes additional
        statistics about projects, files, and patterns.

        Args:
            output_file: Optional path to save the summary to JSON
        """
        summary = self.generate_findings_summary()

        # Print to console
        print("\nAll Findings Summary (Detailed):")
        print("=" * 80)

        for rule_id, data in summary.items():
            print(f"\n{rule_id}:")
            print(f"  Total Findings: {data['total_findings']}")

            print("  Tool Statistics:")
            for tool, stats in data["tool_statistics"].items():
                print(f"    {tool}:")
                print(f"      Total Findings: {stats['total_findings']}")
                print(f"      Unique Projects: {stats['unique_projects']}")
                print(f"      Unique Files: {stats['unique_files']}")
                print(f"      Avg Findings per File: {stats['avg_findings_per_file']}")

                if stats["common_file_patterns"]:
                    print("      Most Common File Types:")
                    for filename, count in stats["common_file_patterns"].items():
                        print(f"        - {filename}: {count} findings")

            print("\n  Overall Statistics:")
            overall = data["overall_statistics"]
            print(f"    Total Unique Projects: {overall['total_unique_projects']}")
            print(f"    Total Unique Files: {overall['total_unique_files']}")
            print(f"    Avg Findings per File: {overall['avg_findings_per_file']}")

        # Save to file if requested
        if output_file:
            with open(output_file, "w") as f:
                json.dump(summary, f, indent=2)

    def generate_findings_summary(self) -> Dict:
        """Generate a detailed summary of all findings across rules and tools.

        Returns:
            Dict containing comprehensive statistics about all findings, including:
            - Distribution of findings across projects
            - Common patterns in detection locations
            - Tool-specific statistics
        """
        summary = {}

        for rule_id, findings in sorted(self.all_detections_per_rule.items()):
            if not findings:
                continue

            # Group findings by tool
            tool_findings = {tool: [] for tool in self.tools}
            for finding in findings:
                tool_findings[finding.tool].append(finding)

            # Calculate tool-specific statistics
            tool_stats = {}
            for tool in self.tools:
                tool_fs = tool_findings[tool]
                if not tool_fs:
                    continue

                # Count unique projects and files
                unique_projects = len(set(f.project_dir for f in tool_fs))
                unique_files = len(set(f.file_path for f in tool_fs))
                avg_per_file = len(tool_fs) / unique_files if unique_files > 0 else 0

                # Calculate file patterns (using only filenames for privacy)
                file_patterns = {}
                for f in tool_fs:
                    filename = Path(f.file_path).name
                    file_patterns[filename] = file_patterns.get(filename, 0) + 1

                # Get top 5 most common file patterns
                top_file_patterns = dict(
                    sorted(file_patterns.items(), key=lambda x: x[1], reverse=True)[:5]
                )

                tool_stats[tool] = {
                    "total_findings": len(tool_fs),
                    "unique_projects": unique_projects,
                    "unique_files": unique_files,
                    "avg_findings_per_file": round(avg_per_file, 2),
                    "common_file_patterns": top_file_patterns,
                }

            # Calculate overall statistics
            all_projects = set(f.project_dir for f in findings)
            all_files = set(f.file_path for f in findings)
            avg_findings_per_file = len(findings) / len(all_files) if all_files else 0

            summary[rule_id] = {
                "total_findings": len(findings),
                "tool_statistics": tool_stats,
                "overall_statistics": {
                    "total_unique_projects": len(all_projects),
                    "total_unique_files": len(all_files),
                    "avg_findings_per_file": round(avg_findings_per_file, 2),
                },
            }

        return summary
