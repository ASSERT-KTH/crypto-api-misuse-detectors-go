#!/usr/bin/env python3
"""
Batch Findings Collector

This module handles collection and aggregation of findings across multiple projects.
It discovers projects, collects findings, and maintains mappings of locations to tools.
"""

from pathlib import Path
from typing import Dict, Set, List
from core.analyzer import Analyzer
from core.findings import Finding


class FindingsCollector:
    """Collects and aggregates findings across multiple projects."""

    def __init__(self, base_dir: Path):
        """Initialize the collector with a base directory.

        Args:
            base_dir: Base directory containing project subdirectories
        """
        self.base_dir = base_dir
        self.project_dirs = self._find_project_dirs()
        self.tool_detections_per_location: Dict[str, Set[str]] = {}
        self.all_detections_per_rule: Dict[str, List[Finding]] = {}
        self.project_findings_data = {}  # Project-specific findings for summary and per-rule analysis

    def _find_project_dirs(self) -> list[Path]:
        """Find all project directories under the base directory.

        Returns:
            list[Path]: List of project directories containing tool findings
        """
        project_dirs = []
        for item in self.base_dir.iterdir():
            if item.is_dir() and any(
                (item / tool).exists() for tool in ["codeql", "gosec", "gopher", "snyk"]
            ):
                project_dirs.append(item)
        return project_dirs

    def _update_all_detections_per_rule(self, rule_map: Dict[str, List[Finding]]):
        """Update the all_detections_per_rule mapping with findings from a project.

        Args:
            rule_map: Dictionary mapping rule IDs to lists of findings
        """
        for rule_id, findings in rule_map.items():
            if rule_id not in self.all_detections_per_rule:
                self.all_detections_per_rule[rule_id] = []
            self.all_detections_per_rule[rule_id].extend(findings)

    def _update_tool_detections_per_location(
        self, location_map: Dict[str, List[Finding]]
    ):
        """Update the tool_detections_per_location mapping with findings from a project.

        Args:
            location_map: Dictionary mapping locations to lists of findings
        """
        for location, findings in location_map.items():
            if location not in self.tool_detections_per_location:
                self.tool_detections_per_location[location] = set()
            else:
                print(
                    f"Warning: Duplicate location {location} found in project {self.base_dir.name}. Locations should be unique."
                )
            self.tool_detections_per_location[location].update(f.tool for f in findings)

    def _process_project_findings(self, project_dir: Path) -> bool:
        """Process findings for a single project and update tool_detections_per_location.

        Args:
            project_dir: Path to the project directory

        Returns:
            bool: True if project was processed successfully, False otherwise
        """
        try:
            analyzer = Analyzer(project_dir)
            analyzer.load_findings()
            location_map, all_detections_by_rules = analyzer.build_detection_maps()

            # Update location_tools with findings from this project
            self._update_tool_detections_per_location(location_map)

            # Update rule-based findings
            self._update_all_detections_per_rule(all_detections_by_rules)

            # Store project findings - this is apparently needed somewhere, do not remove
            self.project_findings_data[project_dir.name] = {
                "location_map": location_map,
            }

            return True

        except Exception as e:
            print(f"  Error processing {project_dir.name}: {e}")
            return False

    def _collect_canonical_ids(self) -> Set[str]:
        """Collect all canonical rule IDs across all projects.

        Returns:
            Set[str]: All canonical rule IDs
        """
        all_canonical_ids = set()

        for project_dir in self.project_dirs:
            try:
                analyzer = Analyzer(project_dir)
                analyzer.load_findings()

                if not any(findings for findings in analyzer.findings.values()):
                    continue

                # Collect canonical rules and groups
                for tool, findings in analyzer.findings.items():
                    for finding in findings:
                        all_canonical_ids.update(finding.canonical_ids)

            except Exception as e:
                print(f"  Error collecting IDs from {project_dir.name}: {e}")
                continue

        return all_canonical_ids

    def collect_all_findings(self) -> Dict:
        """Collects findings from all projects.

        Returns:
            Dict: Dictionary containing:
                - location_tools: Mapping of locations to detecting tools
                - canonical_ids: All canonical rule IDs
                - project_findings: Project-specific findings data
                - consensus_scores: Consensus scores for all rules
        """
        print(f"Found {len(self.project_dirs)} project directories to analyze")

        # Process each project and collect findings
        for project_dir in self.project_dirs:
            print(f"Analyzing {project_dir.name}...")
            self._process_project_findings(project_dir)

        # Collect all canonical IDs
        all_canonical_ids = self._collect_canonical_ids()

        return {
            "location_tools": self.tool_detections_per_location,
            "canonical_ids": all_canonical_ids,
            "project_findings": self.project_findings_data,
        }
