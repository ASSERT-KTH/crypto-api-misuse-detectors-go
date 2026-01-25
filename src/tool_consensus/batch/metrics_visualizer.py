#!/usr/bin/env python3
"""
Metrics Visualizer

This module generates various visualizations from analyzed metrics data, including:
- Consensus score heatmaps
- Alarm rate heatmaps
- Venn diagrams
- Metrics summaries
"""

import json
from pathlib import Path
from typing import Optional

from .metrics_processor import MetricsProcessor
from .venn_generator import VennDiagramGenerator


class MetricsVisualizer(MetricsProcessor):
    """Generates various visualizations from analyzed metrics data."""

    def generate_venn_diagrams(self, output_dir: Path) -> None:
        """Generate Venn diagrams for tool overlaps.

        Args:
            output_dir: Directory to save the generated Venn diagrams
        """
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Use the existing VennDiagramGenerator for Venn diagrams
        venn_generator = VennDiagramGenerator(self.metrics, self.tools)
        venn_generator.generate_venn_diagrams(output_dir)

    def generate_metrics_summary(self, output_path: Optional[Path] = None) -> None:
        """Generate and optionally save a metrics summary.

        Args:
            output_path: Optional path to save the metrics summary JSON
        """
        # Generate metrics JSON
        metrics_json = self.generate_metrics_json()

        # Print summary to console
        self._print_metrics_summary(metrics_json)

        # Save to JSON if path provided
        if output_path:
            with open(output_path, "w") as f:
                json.dump(metrics_json, f, indent=2)

    def _print_metrics_summary(self, metrics_json: dict) -> None:
        """Print a human-readable summary of the metrics.

        Args:
            metrics_json: The metrics JSON data
        """
        print("\nMetrics Summary")
        print("=" * 80)

        # Overall metrics
        overall = metrics_json["overall"]
        print(f"\nOverall Statistics:")
        print(f"  Total Projects: {overall['total_projects']}")
        print(f"  Total Locations: {overall['total_locations']}")
        print("\n  Tool Detections:")
        for tool, data in overall["tool_detections"].items():
            print(f"    {self.tool_display_names[tool]}:")
            print(f"      Count: {data['count']}")
            print(f"      Percentage: {data['percentage']:.1f}%")

        # Top rules by consensus
        print("\nTop Rules by Consensus Score:")
        rules = sorted(
            metrics_json["per_rule"].items(),
            key=lambda x: x[1]["consensus_score"],
            reverse=True,
        )[:5]
        for rule_id, data in rules:
            print(f"\n  {rule_id}:")
            print(f"    Consensus Score: {data['consensus_score']:.2f}")
            print(f"    Total Locations: {data['total_locations']}")
            print(
                f"    Implementing Tools: {', '.join(sorted(data['implementing_tools']))}"
            )
