#!/usr/bin/env python3
"""
Venn Metrics Analyzer

This module analyzes findings data to generate metrics suitable for Venn diagrams,
including overall tool overlap and per-rule metrics.
"""

from typing import Dict, Set, List
from pathlib import Path
import random
import json


class VennMetricsAnalyzer:
    """Analyzes findings to generate Venn diagram metrics."""

    def __init__(self, findings_data: Dict):
        """Initialize the analyzer with collected findings data.

        Args:
            findings_data: Dictionary containing:
                - location_tools: Mapping of locations to detecting tools
                - canonical_ids: All canonical rule IDs
                - project_findings: Project-specific findings data
        """
        self.findings_data = findings_data
        self.metrics = {
            "overall": {
                "tool_counts": {
                    "codeql": 0,
                    "gosec": 0,
                    "gopher": 0,
                    "snyk": 0,
                    "codeql_gosec": 0,
                    "codeql_gopher": 0,
                    "codeql_snyk": 0,
                    "gosec_gopher": 0,
                    "gosec_snyk": 0,
                    "gopher_snyk": 0,
                    "codeql_gosec_gopher": 0,
                    "codeql_gosec_snyk": 0,
                    "codeql_gopher_snyk": 0,
                    "gosec_gopher_snyk": 0,
                    "codeql_gosec_gopher_snyk": 0,
                },
                "total_locations": 0,
            },
            "per_rule": {},
            "projects": findings_data.get("project_findings", {}),
            "sampling_data": {
                "per_rule": {},
            },
        }

    def _calculate_overall_metrics(self):
        """Calculate overall metrics from all unique locations."""
        # Reset tool counts
        for key in self.metrics["overall"]["tool_counts"]:
            self.metrics["overall"]["tool_counts"][key] = 0

        # Set total locations to number of unique locations
        location_tools = self.findings_data["location_tools"]
        self.metrics["overall"]["total_locations"] = len(location_tools)

        # Count tool detections across all unique locations
        for tools in location_tools.values():
            # Count individual tool detections
            if "codeql" in tools:
                self.metrics["overall"]["tool_counts"]["codeql"] += 1
            if "gosec" in tools:
                self.metrics["overall"]["tool_counts"]["gosec"] += 1
            if "gopher" in tools:
                self.metrics["overall"]["tool_counts"]["gopher"] += 1
            if "snyk" in tools:
                self.metrics["overall"]["tool_counts"]["snyk"] += 1

            # Count pairwise overlaps
            if "codeql" in tools and "gosec" in tools:
                self.metrics["overall"]["tool_counts"]["codeql_gosec"] += 1
            if "codeql" in tools and "gopher" in tools:
                self.metrics["overall"]["tool_counts"]["codeql_gopher"] += 1
            if "codeql" in tools and "snyk" in tools:
                self.metrics["overall"]["tool_counts"]["codeql_snyk"] += 1
            if "gosec" in tools and "gopher" in tools:
                self.metrics["overall"]["tool_counts"]["gosec_gopher"] += 1
            if "gosec" in tools and "snyk" in tools:
                self.metrics["overall"]["tool_counts"]["gosec_snyk"] += 1
            if "gopher" in tools and "snyk" in tools:
                self.metrics["overall"]["tool_counts"]["gopher_snyk"] += 1

            # Count triple overlaps
            if "codeql" in tools and "gosec" in tools and "gopher" in tools:
                self.metrics["overall"]["tool_counts"]["codeql_gosec_gopher"] += 1
            if "codeql" in tools and "gosec" in tools and "snyk" in tools:
                self.metrics["overall"]["tool_counts"]["codeql_gosec_snyk"] += 1
            if "codeql" in tools and "gopher" in tools and "snyk" in tools:
                self.metrics["overall"]["tool_counts"]["codeql_gopher_snyk"] += 1
            if "gosec" in tools and "gopher" in tools and "snyk" in tools:
                self.metrics["overall"]["tool_counts"]["gosec_gopher_snyk"] += 1

            # Count quadruple overlap
            if (
                "codeql" in tools
                and "gosec" in tools
                and "gopher" in tools
                and "snyk" in tools
            ):
                self.metrics["overall"]["tool_counts"]["codeql_gosec_gopher_snyk"] += 1

    def _calculate_rule_metrics(self, canon_id: str) -> Dict:
        """Calculate metrics for a specific canonical rule across all projects.

        Args:
            canon_id: Canonical rule ID to analyze

        Returns:
            Dict: Metrics for the specified rule
        """
        metrics = {
            "tool_counts": {
                "codeql": 0,
                "gosec": 0,
                "gopher": 0,
                "snyk": 0,
                "codeql_gosec": 0,
                "codeql_gopher": 0,
                "codeql_snyk": 0,
                "gosec_gopher": 0,
                "gosec_snyk": 0,
                "gopher_snyk": 0,
                "codeql_gosec_gopher": 0,
                "codeql_gosec_snyk": 0,
                "codeql_gopher_snyk": 0,
                "gosec_gopher_snyk": 0,
                "codeql_gosec_gopher_snyk": 0,
            },
            "total_locations": 0,
            "locations": [],
            "projects": {},
        }

        # Aggregate metrics from all projects
        for project_name, project_data in self.findings_data[
            "project_findings"
        ].items():
            location_map = project_data["location_map"]
            project_metrics = self._calculate_rule_metrics_for_project(
                canon_id, location_map
            )
            metrics["projects"][project_name] = project_metrics

            # Update overall counts
            metrics["total_locations"] += project_metrics["total_locations"]
            metrics["locations"].extend(project_metrics["locations"])

            # Update tool counts
            for key in metrics["tool_counts"]:
                metrics["tool_counts"][key] += project_metrics["tool_counts"][key]

        return metrics

    def _calculate_rule_metrics_for_project(
        self, canon_id: str, location_map: dict
    ) -> Dict:
        """Calculate metrics for a specific canonical rule in a single project.

        Args:
            canon_id: Canonical rule ID to analyze
            location_map: Mapping of locations to findings

        Returns:
            Dict: Project-specific metrics for the rule
        """
        metrics = {
            "tool_counts": {
                "codeql": 0,
                "gosec": 0,
                "gopher": 0,
                "snyk": 0,
                "codeql_gosec": 0,
                "codeql_gopher": 0,
                "codeql_snyk": 0,
                "gosec_gopher": 0,
                "gosec_snyk": 0,
                "gopher_snyk": 0,
                "codeql_gosec_gopher": 0,
                "codeql_gosec_snyk": 0,
                "codeql_gopher_snyk": 0,
                "gosec_gopher_snyk": 0,
                "codeql_gosec_gopher_snyk": 0,
            },
            "total_locations": 0,
            "locations": [],
        }

        for location, findings in location_map.items():
            has_canon = False
            location_tools = set()

            for finding in findings:
                if canon_id in finding.canonical_ids:
                    has_canon = True
                    location_tools.add(finding.tool)

            if has_canon:
                metrics["total_locations"] += 1
                metrics["locations"].append(location)

                # Count tool detections
                if "codeql" in location_tools:
                    metrics["tool_counts"]["codeql"] += 1
                if "gosec" in location_tools:
                    metrics["tool_counts"]["gosec"] += 1
                if "gopher" in location_tools:
                    metrics["tool_counts"]["gopher"] += 1
                if "snyk" in location_tools:
                    metrics["tool_counts"]["snyk"] += 1

                # Count pairwise overlaps
                if "codeql" in location_tools and "gosec" in location_tools:
                    metrics["tool_counts"]["codeql_gosec"] += 1
                if "codeql" in location_tools and "gopher" in location_tools:
                    metrics["tool_counts"]["codeql_gopher"] += 1
                if "codeql" in location_tools and "snyk" in location_tools:
                    metrics["tool_counts"]["codeql_snyk"] += 1
                if "gosec" in location_tools and "gopher" in location_tools:
                    metrics["tool_counts"]["gosec_gopher"] += 1
                if "gosec" in location_tools and "snyk" in location_tools:
                    metrics["tool_counts"]["gosec_snyk"] += 1
                if "gopher" in location_tools and "snyk" in location_tools:
                    metrics["tool_counts"]["gopher_snyk"] += 1

                # Count triple overlaps
                if (
                    "codeql" in location_tools
                    and "gosec" in location_tools
                    and "gopher" in location_tools
                ):
                    metrics["tool_counts"]["codeql_gosec_gopher"] += 1
                if (
                    "codeql" in location_tools
                    and "gosec" in location_tools
                    and "snyk" in location_tools
                ):
                    metrics["tool_counts"]["codeql_gosec_snyk"] += 1
                if (
                    "codeql" in location_tools
                    and "gopher" in location_tools
                    and "snyk" in location_tools
                ):
                    metrics["tool_counts"]["codeql_gopher_snyk"] += 1
                if (
                    "gosec" in location_tools
                    and "gopher" in location_tools
                    and "snyk" in location_tools
                ):
                    metrics["tool_counts"]["gosec_gopher_snyk"] += 1

                # Count quadruple overlap
                if (
                    "codeql" in location_tools
                    and "gosec" in location_tools
                    and "gopher" in location_tools
                    and "snyk" in location_tools
                ):
                    metrics["tool_counts"]["codeql_gosec_gopher_snyk"] += 1

        return metrics

    def _calculate_percentages(self, metric_type: str, key: str = None):
        """Calculate percentage metrics for a specific metric type.

        Args:
            metric_type: Type of metrics ("overall" or "per_rule")
            key: Optional key for per_rule metrics
        """
        if metric_type == "overall":
            metrics = self.metrics["overall"]
        elif metric_type == "per_rule":
            metrics = self.metrics["per_rule"][key]
        else:
            raise ValueError(f"Unknown metric type: {metric_type}")

        total = metrics["total_locations"]
        if total > 0:
            for tool_key in metrics["tool_counts"]:
                metrics[f"{tool_key}_percentage"] = (
                    metrics["tool_counts"][tool_key] / total * 100
                )

    def _categorize_location_agreement(self, location_tools: Set[str]) -> str:
        """Categorize the agreement pattern for a location based on tool detections.

        Args:
            location_tools: Set of tools that detected the location

        Returns:
            str: Agreement pattern category
        """
        # Define the canonical order of tools for consistent pattern names
        tool_order = ["codeql", "gosec", "gopher", "snyk"]

        # Sort tools according to canonical order
        sorted_tools = sorted(location_tools, key=lambda x: tool_order.index(x))

        if len(sorted_tools) == 4:
            return "all_tools"
        elif len(sorted_tools) == 1:
            return f"{sorted_tools[0]}_only"
        elif len(sorted_tools) == 2:
            return f"{sorted_tools[0]}_{sorted_tools[1]}"
        elif len(sorted_tools) == 3:
            return f"{sorted_tools[0]}_{sorted_tools[1]}_{sorted_tools[2]}"
        return "unknown"

    def _categorize_location_disagreement(
        self,
        location_tools: Set[str],
        all_tools: Set[str] = {"codeql", "gosec", "gopher", "snyk"},
    ) -> List[str]:
        """Categorize the disagreement patterns for a location.

        Args:
            location_tools: Set of tools that detected the location
            all_tools: Set of all available tools

        Returns:
            List[str]: List of disagreement patterns
        """
        disagreements = []
        missing_tools = all_tools - location_tools
        present_tools = location_tools

        # If some tools are missing, create disagreement patterns
        if missing_tools:
            for tool in present_tools:
                disagreements.append(f"{tool}_vs_others")
            for tool in missing_tools:
                disagreements.append(f"others_vs_{tool}")

        return disagreements

    def _calculate_sampling_data_for_rule(
        self, canon_id: str, location_map: dict
    ) -> Dict:
        """Calculate sampling data for a specific rule.

        Args:
            canon_id: Canonical rule ID
            location_map: Mapping of locations to findings

        Returns:
            Dict: Sampling data for the rule
        """
        sampling_data = {
            "agreements": {
                "all_tools": [],
                "codeql_only": [],
                "gosec_only": [],
                "gopher_only": [],
                "snyk_only": [],
                "codeql_gosec": [],
                "codeql_gopher": [],
                "codeql_snyk": [],
                "gosec_gopher": [],
                "gosec_snyk": [],
                "gopher_snyk": [],
                "codeql_gosec_gopher": [],
                "codeql_gosec_snyk": [],
                "codeql_gopher_snyk": [],
                "gosec_gopher_snyk": [],
                "codeql_gosec_gopher_snyk": [],
            },
            "disagreements": {
                "codeql_vs_others": [],
                "gosec_vs_others": [],
                "gopher_vs_others": [],
                "snyk_vs_others": [],
                "others_vs_codeql": [],
                "others_vs_gosec": [],
                "others_vs_gopher": [],
                "others_vs_snyk": [],
            },
        }

        for location, findings in location_map.items():
            has_canon = False
            location_tools = set()

            for finding in findings:
                if canon_id in finding.canonical_ids:
                    has_canon = True
                    location_tools.add(finding.tool)

            if has_canon:
                # Categorize agreement
                agreement_pattern = self._categorize_location_agreement(location_tools)
                if agreement_pattern in sampling_data["agreements"]:
                    sampling_data["agreements"][agreement_pattern].append(location)

                # Categorize disagreements
                disagreement_patterns = self._categorize_location_disagreement(
                    location_tools
                )
                for pattern in disagreement_patterns:
                    if pattern in sampling_data["disagreements"]:
                        sampling_data["disagreements"][pattern].append(location)

        return sampling_data

    def analyze_metrics(self) -> Dict:
        """Analyzes findings to generate Venn metrics.

        Returns:
            Dict: Complete metrics dictionary including overall and per-rule metrics
        """
        # Calculate overall metrics
        self._calculate_overall_metrics()
        self._calculate_percentages("overall")

        # Calculate metrics for each canonical rule
        for canon_id in self.findings_data["canonical_ids"]:
            # Calculate regular metrics
            self.metrics["per_rule"][canon_id] = self._calculate_rule_metrics(canon_id)
            self._calculate_percentages("per_rule", canon_id)

            # Calculate sampling data
            sampling_data = {}
            for project_name, project_data in self.findings_data[
                "project_findings"
            ].items():
                location_map = project_data["location_map"]
                sampling_data[project_name] = self._calculate_sampling_data_for_rule(
                    canon_id, location_map
                )
            self.metrics["sampling_data"]["per_rule"][canon_id] = sampling_data

        return self.metrics

    def sample_agreement_patterns(
        self,
        max_samples_per_pattern: int = 5,
        output_file: Path = None,
        include_patterns: List[str] = None,
    ) -> Dict:
        """Sample locations from agreement and disagreement patterns.

        Args:
            max_samples_per_pattern: Maximum number of samples to take per pattern (default: 5)
            output_file: Optional path to save samples to JSON
            include_patterns: Optional list of patterns to include (e.g., ["all_tools", "codeql_only"])

        Returns:
            Dict containing sampled locations per pattern, organized by rule
        """
        samples = {
            "per_rule": {},
        }

        # Define which patterns to sample from
        if include_patterns is None:
            include_patterns = [
                "all_tools",  # All tools agree
                "codeql_only",  # Only CodeQL
                "gosec_only",  # Only Gosec
                "gopher_only",  # Only Gopher
                "snyk_only",  # Only Snyk
                "codeql_gosec",  # CodeQL and Gosec agree
                "codeql_gopher",  # CodeQL and Gopher agree
                "codeql_snyk",  # CodeQL and Snyk agree
                "gosec_gopher",  # Gosec and Gopher agree
                "gosec_snyk",  # Gosec and Snyk agree
                "gopher_snyk",  # Gopher and Snyk agree
            ]

        # Sample from rules
        for rule_id, rule_data in self.metrics["sampling_data"]["per_rule"].items():
            samples["per_rule"][rule_id] = {}

            # Aggregate locations across all projects for each pattern
            pattern_locations = {pattern: [] for pattern in include_patterns}
            for project_name, project_data in rule_data.items():
                for pattern in include_patterns:
                    if pattern in project_data["agreements"]:
                        pattern_locations[pattern].extend(
                            project_data["agreements"][pattern]
                        )

            # Sample from each pattern
            for pattern, locations in pattern_locations.items():
                if locations:
                    n_samples = min(max_samples_per_pattern, len(locations))
                    sampled_locations = random.sample(locations, n_samples)
                    samples["per_rule"][rule_id][pattern] = {
                        "locations": sampled_locations,
                        "total_locations": len(locations),
                        "sampled_count": n_samples,
                    }

        # Save to file if requested
        if output_file:
            with open(output_file, "w") as f:
                json.dump(samples, f, indent=2)

        return samples

    def print_sampling_summary(self, samples: Dict) -> None:
        """Print summary of sampling results.

        Args:
            samples: Dictionary of sampled locations
        """
        print("\nSampling Summary:")
        print("=" * 80)

        # Print rule samples
        if samples["per_rule"]:
            print("\nRule Samples:")
            for rule_id, patterns in sorted(samples["per_rule"].items()):
                if not patterns:
                    continue
                print(f"\n{rule_id}:")
                for pattern, data in patterns.items():
                    print(f"  {pattern}:")
                    print(
                        f"    - Sampled {data['sampled_count']} of {data['total_locations']} locations"
                    )

        # No group sampling when using canonical-only analysis
