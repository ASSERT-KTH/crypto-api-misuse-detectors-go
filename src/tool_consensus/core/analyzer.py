import sys
import json
from typing import Dict, List, Any, Tuple
from pathlib import Path
from core.findings import Finding
from core.parsers import CodeQLParser, GosecParser, SnykParser, GopherParser


class Analyzer:
    """Main analyzer class for comparing tool outputs."""

    def __init__(self, project_dir: Path):
        """Initialize analyzer with project directory.

        Args:
            project_dir: Path to project directory containing tool outputs
        """
        self.project_dir = project_dir
        self.findings: Dict[str, List[Finding]] = {
            "codeql": [],
            "gosec": [],
            "gopher": [],
            "snyk": [],
        }

        # Load canonicalized mappings once
        self.canonicalized_mappings = self._load_canonicalized_mappings()

        # Initialize parsers with project directory name and shared mappings
        project_name = project_dir.name
        self.codeql_parser = CodeQLParser(project_name, self.canonicalized_mappings)
        self.gosec_parser = GosecParser(project_name, self.canonicalized_mappings)
        self.gopher_parser = GopherParser(project_name, self.canonicalized_mappings)
        self.snyk_parser = SnykParser(project_name, self.canonicalized_mappings)

    def _load_canonicalized_mappings(self) -> List[Dict[str, Any]]:
        """Load the canonicalized rule mappings from JSON file."""
        rules_path = (
            Path(__file__).parent / "rules" / "canonicalized_rule_mappings.json"
        )
        try:
            with open(rules_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error loading canonicalized rule mappings: {e}", file=sys.stderr)
            return []


    def load_findings(self):
        """Load findings from all tools."""
        # Load CodeQL findings
        codeql_dir = self.project_dir / "codeql"
        if codeql_dir.exists():
            self.findings["codeql"] = self.codeql_parser.parse_directory(codeql_dir)

        # Load Gosec findings
        gosec_file = self.project_dir / "gosec" / "results.json"
        if gosec_file.exists():
            self.findings["gosec"] = self.gosec_parser.parse_file(gosec_file)

        # Load Gopher findings
        gopher_file = self.project_dir / "gopher" / "results.json"
        if gopher_file.exists():
            self.findings["gopher"] = self.gopher_parser.parse_file(gopher_file)

        # Load Snyk findings
        snyk_file = self.project_dir / "snyk" / "results.json"
        if snyk_file.exists():
            self.findings["snyk"] = self.snyk_parser.parse_file(snyk_file)

    def build_detection_maps(
        self,
    ) -> Tuple[Dict[str, List[Finding]], Dict[str, List[Finding]]]:
        """Build two maps of findings grouped by their location on line-level, one for each tool type

        Returns:
            Dictionary mapping location keys to lists of findings at that location.
        """
        line_level_detections: Dict[str, List[Finding]] = {}
        all_detections_per_rule: Dict[str, List[Finding]] = {}

        if not self.findings:
            print("No findings loaded from any tools.")
            return line_level_detections

        for tool, tool_findings in self.findings.items():
            for finding in tool_findings:
                key = finding.get_match_key()
                if key not in line_level_detections:
                    line_level_detections[key] = []
                line_level_detections[key].append(finding)

                # Group findings by canonical rule IDs
                if not finding.canonical_ids:
                    # Skip findings without canonical IDs
                    continue
                for canonical_id in finding.canonical_ids:
                    all_detections_per_rule.setdefault(canonical_id, []).append(finding)

        return (line_level_detections, all_detections_per_rule)
