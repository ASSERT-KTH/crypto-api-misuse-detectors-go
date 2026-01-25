#!/usr/bin/env python3
"""
Metrics Processor

This module provides base functionality for processing and transforming metrics data.
It serves as a foundation for various visualization and analysis tools.
"""

from typing import Dict, List, Set


class MetricsProcessor:
    """Base class for processing and transforming metrics data."""

    def __init__(self, metrics: Dict, tools: List[str] = None):
        """Initialize the metrics processor.

        Args:
            metrics: Dictionary containing analyzed metrics for:
                - overall tool overlap
                - per-rule metrics
            tools: Optional list of tool names to include (default: ['codeql', 'gosec', 'gopher', 'snyk'])
        """
        self.metrics = metrics
        self.tools = tools or ["codeql", "gosec", "gopher", "snyk"]
        self.tool_display_names = {
            "codeql": "CodeQL",
            "gosec": "Gosec",
            "gopher": "Gopher",
            "snyk": "Snyk",
        }

    def calculate_rule_consensus(self, metrics: Dict, rule_id: str) -> float:
        """Calculate consensus score for a rule according to the defined formula.

        Args:
            metrics: Metrics dictionary containing detection data
            rule_id: The rule ID to calculate consensus for

        Returns:
            float: Consensus score between 0 and 1
        """
        # Get the set of tools that implement this rule (T_r)
        implementing_tools = self._get_implementing_tools(metrics)

        if not implementing_tools:
            return 0.0

        # Calculate total detections (|D_r|)
        total_detections = metrics["total_locations"]
        if total_detections == 0:
            return 0.0

        # Calculate total weighted detections using inclusion-exclusion principle
        total_tool_detections = sum(
            metrics["tool_counts"][tool] for tool in implementing_tools
        )

        # Calculate overlaps
        pair_overlaps = self._calculate_pair_overlaps(metrics, implementing_tools)
        triple_overlaps = self._calculate_triple_overlaps(metrics, implementing_tools)
        all_tools_overlap = self._calculate_all_tools_overlap(
            metrics, implementing_tools
        )

        # Calculate total weighted detections
        total_weighted_detections = (
            total_tool_detections - pair_overlaps + triple_overlaps - all_tools_overlap
        )

        # Calculate consensus score
        consensus = (
            total_weighted_detections / len(implementing_tools)
        ) / total_detections
        return consensus

    def _get_implementing_tools(self, metrics: Dict) -> Set[str]:
        """Get the set of tools that implement a rule.

        Args:
            metrics: Metrics dictionary containing detection data

        Returns:
            Set[str]: Set of tool names that implement the rule
        """
        return {tool for tool in self.tools if metrics["tool_counts"][tool] > 0}

    def _calculate_pair_overlaps(
        self, metrics: Dict, implementing_tools: Set[str]
    ) -> int:
        """Calculate pairwise tool overlaps.

        Args:
            metrics: Metrics dictionary containing detection data
            implementing_tools: Set of tools implementing the rule

        Returns:
            int: Total number of pairwise overlaps
        """
        pair_overlaps = 0
        for t1, t2 in [
            ("codeql", "gosec"),
            ("codeql", "gopher"),
            ("codeql", "snyk"),
            ("gosec", "gopher"),
            ("gosec", "snyk"),
            ("gopher", "snyk"),
        ]:
            if t1 in implementing_tools and t2 in implementing_tools:
                pair_key = f"{t1}_{t2}"
                pair_overlaps += metrics["tool_counts"].get(pair_key, 0)
        return pair_overlaps

    def _calculate_triple_overlaps(
        self, metrics: Dict, implementing_tools: Set[str]
    ) -> int:
        """Calculate triple tool overlaps.

        Args:
            metrics: Metrics dictionary containing detection data
            implementing_tools: Set of tools implementing the rule

        Returns:
            int: Total number of triple overlaps
        """
        triple_overlaps = 0
        for t1, t2, t3 in [
            ("codeql", "gosec", "gopher"),
            ("codeql", "gosec", "snyk"),
            ("codeql", "gopher", "snyk"),
            ("gosec", "gopher", "snyk"),
        ]:
            if (
                t1 in implementing_tools
                and t2 in implementing_tools
                and t3 in implementing_tools
            ):
                triple_key = f"{t1}_{t2}_{t3}"
                triple_overlaps += metrics["tool_counts"].get(triple_key, 0)
        return triple_overlaps

    def _calculate_all_tools_overlap(
        self, metrics: Dict, implementing_tools: Set[str]
    ) -> int:
        """Calculate overlap between all tools.

        Args:
            metrics: Metrics dictionary containing detection data
            implementing_tools: Set of tools implementing the rule

        Returns:
            int: Number of locations detected by all tools
        """
        if len(implementing_tools) == 4:
            return metrics["tool_counts"].get("codeql_gosec_gopher_snyk", 0)
        return 0

    def generate_metrics_json(self) -> dict:
        """Generate a structured JSON representation of metrics for visualization.

        Returns:
            dict: A dictionary containing metrics in a format suitable for visualization
        """
        metrics_json = {
            "overall": {
                "total_projects": len(self.metrics["projects"]),
                "total_locations": self.metrics["overall"]["total_locations"],
                "tool_detections": {
                    tool: {
                        "count": self.metrics["overall"]["tool_counts"][tool],
                        "percentage": self.metrics["overall"].get(
                            f"{tool}_percentage", 0
                        ),
                    }
                    for tool in self.tools
                },
            },
            "per_rule": {
                rule_id: {
                    "total_locations": metrics["total_locations"],
                    "consensus_score": self.calculate_rule_consensus(metrics, rule_id),
                    "implementing_tools": sorted(
                        list(self._get_implementing_tools(metrics))
                    ),
                    "tool_detections": {
                        tool: {
                            "count": metrics["tool_counts"][tool],
                            "percentage": metrics.get(f"{tool}_percentage", 0),
                        }
                        for tool in self.tools
                    },
                }
                for rule_id, metrics in self.metrics["per_rule"].items()
            },
        }
        return metrics_json
