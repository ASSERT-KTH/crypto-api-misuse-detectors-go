#!/usr/bin/env python3
"""
Venn Diagram Generator

This module generates Venn diagrams and metrics summaries from analyzed findings data.
It handles the visualization of tool overlap metrics for overall findings, per-rule,
and per-rule analysis.
"""

import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from venn import venn
from typing import Dict, Set, List

from core.venn_math import (
    calculate_venn_regions,
    calculate_venn_regions_4set,
    validate_venn_calculations_4set,
)


class VennDiagramGenerator:
    """Generates Venn diagrams using the venn library for better scalability.

    This generator supports arbitrary numbers of tools (2-6) and handles
    visualization in a way that scales better than matplotlib-venn.
    """

    def __init__(self, metrics: Dict, tools: List[str] = None):
        """Initialize the generator with analyzed metrics.

        Args:
            metrics: Dictionary containing analyzed metrics for:
                - overall tool overlap
                - per-rule metrics
            tools: Optional list of tool names to include (default: ['codeql', 'gosec', 'gopher', 'snyk'])
                  Can include additional tools for future expansion
        """
        self.metrics = metrics
        self.tools = tools or ["codeql", "gosec", "gopher", "snyk"]
        self.tool_display_names = {
            "codeql": "CodeQL",
            "gosec": "Gosec",
            "gopher": "Gopher",
            "snyk": "Snyk",
        }

    def generate_venn_diagrams(self, output_dir: Path):
        """Generate Venn diagrams for all metrics using the venn library.

        Args:
            output_dir: Directory to save the generated diagrams
        """
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        self._create_venn_diagram(
            self.metrics["overall"],
            output_dir / "overall_venn.png",
            "Overall Tool Detection Overlap Across All Projects",
        )

        # Generate Venn diagrams for all rules
        sorted_rules = sorted(
            self.metrics["per_rule"].items(),
            key=lambda x: x[1]["total_locations"],
            reverse=True,
        )

        # Generate diagrams for all rules
        for rule_id, metrics in sorted_rules:
            print(
                f"Generating Venn diagram for rule {rule_id} ({metrics['total_locations']} locations)"
            )
            self._create_venn_diagram(
                metrics,
                output_dir / f"rule_{rule_id}_venn.png",
                f"Tool Detection Overlap for Rule {rule_id}",
            )

        print(f"\nVenn diagrams saved to {output_dir}")

    def _create_tool_sets_from_metrics(self, metrics: Dict) -> Dict[str, Set[int]]:
        """Create sets from the metrics for use with the venn library.

        Uses the correct mathematical approach for both 3-set and 4-set cases.

        Args:
            metrics: Metrics dictionary with tool counts

        Returns:
            Dict[str, Set[int]]: Dictionary mapping tool names to sets of locations
        """
        # Create empty sets for each tool
        tool_sets = {}
        for tool in self.tools:
            display_name = self.tool_display_names.get(tool, tool.capitalize())
            tool_sets[display_name] = set()

        # Use different approaches based on number of tools
        if len(self.tools) <= 3:
            # Use 3-set calculation
            regions = calculate_venn_regions(metrics)
            element_idx = 0

            # Map tools to indices for 3-set case
            tool_map = {0: "codeql", 1: "gosec", 2: "gopher"}

            # Region 0: Tool A only
            for i in range(regions[0]):
                tool_sets[self.tool_display_names.get(tool_map[0], "CodeQL")].add(
                    element_idx
                )
                element_idx += 1

            # Region 1: Tool B only
            for i in range(regions[1]):
                tool_sets[self.tool_display_names.get(tool_map[1], "Gosec")].add(
                    element_idx
                )
                element_idx += 1

            # Region 2: Tool C only
            for i in range(regions[2]):
                tool_sets[self.tool_display_names.get(tool_map[2], "Gopher")].add(
                    element_idx
                )
                element_idx += 1

            # Region 3: A+B only
            for i in range(regions[3]):
                tool_sets[self.tool_display_names.get(tool_map[0], "CodeQL")].add(
                    element_idx
                )
                tool_sets[self.tool_display_names.get(tool_map[1], "Gosec")].add(
                    element_idx
                )
                element_idx += 1

            # Region 4: A+C only
            for i in range(regions[4]):
                tool_sets[self.tool_display_names.get(tool_map[0], "CodeQL")].add(
                    element_idx
                )
                tool_sets[self.tool_display_names.get(tool_map[2], "Gopher")].add(
                    element_idx
                )
                element_idx += 1

            # Region 5: B+C only
            for i in range(regions[5]):
                tool_sets[self.tool_display_names.get(tool_map[1], "Gosec")].add(
                    element_idx
                )
                tool_sets[self.tool_display_names.get(tool_map[2], "Gopher")].add(
                    element_idx
                )
                element_idx += 1

            # Region 6: A+B+C
            for i in range(regions[6]):
                tool_sets[self.tool_display_names.get(tool_map[0], "CodeQL")].add(
                    element_idx
                )
                tool_sets[self.tool_display_names.get(tool_map[1], "Gosec")].add(
                    element_idx
                )
                tool_sets[self.tool_display_names.get(tool_map[2], "Gopher")].add(
                    element_idx
                )
                element_idx += 1

        elif len(self.tools) == 4:
            # Use 4-set calculation
            regions = calculate_venn_regions_4set(metrics)
            element_idx = 0

            # Map tools to indices for 4-set case
            tool_map = {0: "codeql", 1: "gosec", 2: "gopher", 3: "snyk"}

            # Individual only regions (4)
            for tool_idx in range(4):
                for i in range(regions[tool_idx]):
                    tool_sets[
                        self.tool_display_names.get(
                            tool_map[tool_idx], tool_map[tool_idx].capitalize()
                        )
                    ].add(element_idx)
                    element_idx += 1

            # Pairwise only regions (6) - starting at index 4
            pairs = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]
            for pair_idx, (tool1_idx, tool2_idx) in enumerate(pairs):
                region_idx = 4 + pair_idx
                for i in range(regions[region_idx]):
                    tool_sets[
                        self.tool_display_names.get(
                            tool_map[tool1_idx], tool_map[tool1_idx].capitalize()
                        )
                    ].add(element_idx)
                    tool_sets[
                        self.tool_display_names.get(
                            tool_map[tool2_idx], tool_map[tool2_idx].capitalize()
                        )
                    ].add(element_idx)
                    element_idx += 1

            # Triple only regions (4) - starting at index 10
            triples = [(0, 1, 2), (0, 1, 3), (0, 2, 3), (1, 2, 3)]
            for triple_idx, (tool1_idx, tool2_idx, tool3_idx) in enumerate(triples):
                region_idx = 10 + triple_idx
                for i in range(regions[region_idx]):
                    tool_sets[
                        self.tool_display_names.get(
                            tool_map[tool1_idx], tool_map[tool1_idx].capitalize()
                        )
                    ].add(element_idx)
                    tool_sets[
                        self.tool_display_names.get(
                            tool_map[tool2_idx], tool_map[tool2_idx].capitalize()
                        )
                    ].add(element_idx)
                    tool_sets[
                        self.tool_display_names.get(
                            tool_map[tool3_idx], tool_map[tool3_idx].capitalize()
                        )
                    ].add(element_idx)
                    element_idx += 1

            # Quadruple region (1) - index 14
            for i in range(regions[14]):
                for tool_idx in range(4):
                    tool_sets[
                        self.tool_display_names.get(
                            tool_map[tool_idx], tool_map[tool_idx].capitalize()
                        )
                    ].add(element_idx)
                element_idx += 1

        else:
            # For 5+ tools, fallback to a basic approach (not mathematically precise)
            # This is a placeholder - we'd need to implement higher-order Venn calculations
            print(
                f"Warning: {len(self.tools)}-set Venn diagrams not fully supported. Using basic approximation."
            )
            element_idx = 0
            for tool in self.tools:
                display_name = self.tool_display_names.get(tool, tool.capitalize())
                if tool in metrics["tool_counts"]:
                    for i in range(metrics["tool_counts"][tool]):
                        tool_sets[display_name].add(element_idx)
                        element_idx += 1

        return tool_sets

    def _create_venn_diagram(self, metrics: Dict, output_file: Path, title: str):
        """Create a Venn diagram from tool overlap metrics using venn library.

        Args:
            metrics: Metrics dictionary for the specific analysis
            output_file: Path to save the diagram
            title: Title for the diagram
        """
        plt.figure(figsize=(10, 8))

        if metrics["total_locations"] == 0:
            plt.text(
                0.5,
                0.5,
                "No data available",
                horizontalalignment="center",
                verticalalignment="center",
                transform=plt.gca().transAxes,
                fontsize=14,
            )
            # plt.title(title)
            plt.savefig(output_file)
            plt.close()
            return

        # Filter out tools with no detections
        active_tools = []
        for tool in self.tools:
            if tool in metrics["tool_counts"] and metrics["tool_counts"][tool] > 0:
                active_tools.append(
                    self.tool_display_names.get(tool, tool.capitalize())
                )

        # If no tools have detections, show a message
        if not active_tools:
            plt.text(
                0.5,
                0.5,
                "No detections found",
                horizontalalignment="center",
                verticalalignment="center",
                transform=plt.gca().transAxes,
                fontsize=14,
            )
            plt.title(title)
            plt.savefig(output_file)
            plt.close()
            return

        # If only one tool has detections, show a simple message
        if len(active_tools) == 1:
            tool = active_tools[0]
            plt.text(
                0.5,
                0.5,
                f"Only detected by {tool}: {metrics['tool_counts'][tool.lower()]}",
                horizontalalignment="center",
                verticalalignment="center",
                transform=plt.gca().transAxes,
                fontsize=14,
            )
            plt.title(title)
            plt.savefig(output_file)
            plt.close()
            return

        # Convert the metrics to sets for the venn library
        dataset_dict = self._create_tool_sets_from_metrics(metrics)

        # Filter to include only active tools
        dataset_dict = {k: v for k, v in dataset_dict.items() if k in active_tools}

        # Sort the dataset dictionary keys to ensure consistent colors
        # This ensures CodeQL is always red, Gosec is always blue, Gopher is always green, Snyk is always purple
        # Although the venn library will use colors in consecutive order, so for 2 vs 4 tools we get wrong color
        tool_order = {"CodeQL": 0, "Gosec": 3, "Gopher": 1, "Snyk": 2}
        # tool_order = {"CodeQL": 4, "Gosec": 3, "Gopher": 1, "Snyk": 2}
        sorted_keys = sorted(
            dataset_dict.keys(),
            key=lambda x: tool_order.get(x, 4),  # Default value for any other tools
        )
        dataset_dict = {k: dataset_dict[k] for k in sorted_keys}

        # Add Gopher if not present
        if "Gopher" not in dataset_dict:
            dataset_dict["Gopher"] = set()

        # Get colors from tab20b palette
        colors = sns.color_palette("tab20b", n_colors=20)
        # Select specific colors for our tools (using indices that give good contrast)
        tool_colors = {
            "CodeQL": colors[1],  # purple
            "Gosec": colors[19],  # pink
            "Snyk": colors[10],  # yellow
            "Gopher": colors[13],  # red
        }
                # Generate the Venn diagram
        venn(
            dataset_dict,
            fontsize=14,
            legend_loc="upper left",
            ax=plt.gca(),
            cmap=[tool_colors[tool] for tool in sorted_keys],  # Use our custom colors
            alpha=0.7,
        )
        
        # plt.title(title)
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close()

    def _calculate_rule_consensus(self, metrics: Dict, rule_id: str) -> float:
        """Calculate consensus score for a rule according to the defined formula.

        Args:
            metrics: Metrics dictionary containing detection data
            rule_id: The rule ID to calculate consensus for

        Returns:
            float: Consensus score between 0 and 1
        """
        # Get the set of tools that implement this rule (T_r)
        implementing_tools = set()
        for tool in self.tools:
            if metrics["tool_counts"][tool] > 0:
                implementing_tools.add(tool)

        if not implementing_tools:
            return 0.0

        # Calculate total detections (|D_r|)
        total_detections = metrics["total_locations"]
        if total_detections == 0:
            return 0.0

        # For each location, we need to know how many implementing tools detected it
        # We'll use the inclusion-exclusion principle to calculate this correctly

        # Start with sum of individual tool detections
        total_tool_detections = sum(
            metrics["tool_counts"][tool] for tool in implementing_tools
        )

        # Subtract pairwise overlaps (they were counted twice)
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

        # Add back triple overlaps (they were subtracted too many times)
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

        # Subtract quadruple overlap (it was added back too many times)
        all_tools_overlap = 0
        if len(implementing_tools) == 4:
            all_tools_overlap = metrics["tool_counts"].get(
                "codeql_gosec_gopher_snyk", 0
            )

        # Calculate total unique detections with correct tool counts
        # This is the sum of (number of tools that detected each location)
        total_weighted_detections = (
            total_tool_detections  # Sum of individual detections
            - pair_overlaps  # Subtract pairwise overlaps (counted twice)
            + triple_overlaps  # Add back triple overlaps (subtracted too many times)
            - all_tools_overlap  # Subtract quadruple overlap (added back too many times)
        )

        # Calculate consensus score
        # For each detection, we want count_r(d)/|T_r|
        # total_weighted_detections gives us sum(count_r(d))
        # So we divide by |T_r| and then by total_detections
        consensus = (
            total_weighted_detections / len(implementing_tools)
        ) / total_detections

        return consensus

    def generate_metrics_json(self) -> dict:
        """Generate a structured JSON representation of all metrics.

        Returns:
            dict: A dictionary containing all metrics in a format suitable for visualization.
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
                    for tool in ["codeql", "gosec", "gopher", "snyk"]
                },
                "tool_overlaps": {
                    "pairs": {
                        f"{t1}_{t2}": {
                            "count": self.metrics["overall"]["tool_counts"][
                                f"{t1}_{t2}"
                            ],
                            "percentage": self.metrics["overall"].get(
                                f"{t1}_{t2}_percentage", 0
                            ),
                        }
                        for t1, t2 in [
                            ("codeql", "gosec"),
                            ("codeql", "gopher"),
                            ("codeql", "snyk"),
                            ("gosec", "gopher"),
                            ("gosec", "snyk"),
                            ("gopher", "snyk"),
                        ]
                    },
                    "triples": {
                        f"{t1}_{t2}_{t3}": {
                            "count": self.metrics["overall"]["tool_counts"][
                                f"{t1}_{t2}_{t3}"
                            ],
                            "percentage": self.metrics["overall"].get(
                                f"{t1}_{t2}_{t3}_percentage", 0
                            ),
                        }
                        for t1, t2, t3 in [
                            ("codeql", "gosec", "gopher"),
                            ("codeql", "gosec", "snyk"),
                            ("codeql", "gopher", "snyk"),
                            ("gosec", "gopher", "snyk"),
                        ]
                    },
                    "all_tools": {
                        "count": self.metrics["overall"]["tool_counts"][
                            "codeql_gosec_gopher_snyk"
                        ],
                        "percentage": self.metrics["overall"].get(
                            "codeql_gosec_gopher_snyk_percentage", 0
                        ),
                    },
                },
            },
            "per_rule": {
                rule_id: {
                    "total_locations": metrics["total_locations"],
                    "consensus_score": self._calculate_rule_consensus(metrics, rule_id),
                    "implementing_tools": [
                        tool for tool in self.tools if metrics["tool_counts"][tool] > 0
                    ],
                    "tool_detections": {
                        tool: {
                            "count": metrics["tool_counts"][tool],
                            "percentage": metrics.get(f"{tool}_percentage", 0),
                        }
                        for tool in ["codeql", "gosec", "gopher", "snyk"]
                    },
                    "tool_overlaps": {
                        "all_tools": {
                            "count": metrics["tool_counts"]["codeql_gosec_gopher_snyk"],
                            "percentage": metrics.get(
                                "codeql_gosec_gopher_snyk_percentage", 0
                            ),
                        }
                    },
                }
                for rule_id, metrics in self.metrics["per_rule"].items()
            },
        }
        return metrics_json

    def print_metrics_summary(self, output_json_path: str = None):
        """Print a summary of all metrics and optionally write to JSON.

        Args:
            output_json_path: Optional path to write JSON metrics. If provided, metrics will be written to this file.
        """
        # Generate JSON metrics
        metrics_json = self.generate_metrics_json()

        # Write to JSON file if path is provided
        if output_json_path:
            import json

            with open(output_json_path, "w") as f:
                json.dump(metrics_json, f, indent=2)
            print(f"\nMetrics written to: {output_json_path}")

        # Print summary (keeping existing print functionality)
        print("\nVenn Diagram Metrics Summary")
        print("=" * 80)
        print(f"Total projects analyzed: {metrics_json['overall']['total_projects']}")

        # Overall metrics
        overall = metrics_json["overall"]
        print(f"\nOverall Metrics Across All Projects:")
        print(f"Total unique locations: {overall['total_locations']}")

        if overall["total_locations"] > 0:
            print("\nTool detection counts:")
            for tool, data in overall["tool_detections"].items():
                print(f"  {tool.title()}: {data['count']} ({data['percentage']:.1f}%)")

            print("\nTool overlap counts:")
            for pair, data in overall["tool_overlaps"]["pairs"].items():
                tools = pair.split("_")
                print(
                    f"  {' + '.join(t.title() for t in tools)}: {data['count']} ({data['percentage']:.1f}%)"
                )

            print("\nTriple overlap counts:")
            for triple, data in overall["tool_overlaps"]["triples"].items():
                tools = triple.split("_")
                print(
                    f"  {' + '.join(t.title() for t in tools)}: {data['count']} ({data['percentage']:.1f}%)"
                )

            print("\nQuadruple overlap count:")
            all_tools = overall["tool_overlaps"]["all_tools"]
            print(
                f"  All four tools: {all_tools['count']} ({all_tools['percentage']:.1f}%)"
            )
        else:
            print("\nNo detections found across all projects.")

        # Top rules by total locations
        print("\nTop Rules by Detection Count:")
        sorted_rules = sorted(
            metrics_json["per_rule"].items(),
            key=lambda x: x[1]["total_locations"],
            reverse=True,
        )

        for rule_id, metrics in sorted_rules[:5]:  # Top 5 rules
            print(f"\nRule {rule_id}:")
            print(f"  Total locations: {metrics['total_locations']}")
            print(f"  Consensus score: {metrics['consensus_score']:.3f}")
            print(f"  Implementing tools: {', '.join(metrics['implementing_tools'])}")

            if metrics["total_locations"] > 0:
                print(f"  Tool detection counts:")
                for tool, data in metrics["tool_detections"].items():
                    print(
                        f"    {tool.title()}: {data['count']} ({data['percentage']:.1f}%)"
                    )
                print(f"  Tool overlap counts:")
                all_tools = metrics["tool_overlaps"]["all_tools"]
                print(
                    f"    All four tools: {all_tools['count']} ({all_tools['percentage']:.1f}%)"
                )
            else:
                print("  No detections found for this rule.")
