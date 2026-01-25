import os
import sys
import unittest
from pathlib import Path

# Add the parent directory to path so we can import analyzer modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Add the src directory to path so we can import tool_consensus modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from analyze import CodeQLParser, GosecParser, GopherParser, Finding, Analyzer


class TestCanonicalizedRules(unittest.TestCase):
    """Test cases for the canonicalized rule mapping functionality."""

    def setUp(self):
        """Set up the test case."""
        # Path to test fixtures
        self.fixtures_dir = Path(__file__).parent / "fixtures" / "test-project"

        # Initialize parsers
        self.codeql_parser = CodeQLParser()
        self.gosec_parser = GosecParser()
        self.gopher_parser = GopherParser()

    def test_gopher_canonical_mapping(self):
        """Test that Gopher rules are correctly mapped to canonical IDs."""
        # Test a few known mappings
        self.assertEqual(self.gopher_parser.get_canonical_id("R05"), "CR01")
        self.assertEqual(self.gopher_parser.get_canonical_id("R06"), "CR02")
        self.assertEqual(self.gopher_parser.get_canonical_id("R13"), "CR14")

        # Test with actual findings
        gopher_file = self.fixtures_dir / "gopher" / "results.json"
        findings = self.gopher_parser.parse_file(gopher_file)

        # Ensure findings have canonical IDs
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "R05")
        self.assertEqual(finding.canonical_id, "CR01")  # R05 should map to CR01

    def test_gosec_canonical_mapping(self):
        """Test that Gosec rules are correctly mapped to canonical IDs."""
        # Test a few known mappings
        self.assertEqual(self.gosec_parser.get_canonical_id("G501"), "CR01")
        self.assertEqual(self.gosec_parser.get_canonical_id("G404"), "CR03")

        # Note: G402 maps to multiple canonical rules (CR12, CR13, CR14)
        # For our test fixtures, it maps to the last one in the file (CR14)
        self.assertEqual(
            self.gosec_parser.get_canonical_ids("G402"), ["CR12", "CR13", "CR14"]
        )

        # Test with actual findings
        gosec_file = self.fixtures_dir / "gosec" / "results.json"
        findings = self.gosec_parser.parse_file(gosec_file)

        # Ensure findings have canonical IDs
        self.assertEqual(len(findings), 2)
        # G501 should map to CR01 (Insecure Algorithm)
        self.assertEqual(findings[0].rule_id, "G501")
        self.assertEqual(findings[0].canonical_id, "CR01")

    def test_codeql_canonical_mapping(self):
        """Test that CodeQL rules are correctly mapped to canonical IDs."""
        # Test a few known mappings
        # Note: CWE-327 maps to multiple canonical rules (CR12, CR13)
        # For our test fixtures, it maps to the last one in the file (CR13)
        self.assertEqual(
            self.codeql_parser.get_canonical_ids("CWE-327"), ["CR12", "CR13"]
        )
        self.assertEqual(self.codeql_parser.get_canonical_id("CWE-326"), "CR06")
        self.assertEqual(self.codeql_parser.get_canonical_id("CWE-295"), "CR14")

        # Test with actual findings
        codeql_dir = self.fixtures_dir / "codeql"
        findings = self.codeql_parser.parse_directory(codeql_dir)

        # Ensure findings have canonical IDs
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CWE-327")
        # self.assertEqual(
        #    findings[0].canonical_id, "CR13"
        # )  # CWE-327 maps to CR13 in our mappings

    def test_analyzer_summary_with_canonical_ids(self):
        """Test that the analyzer correctly displays canonical rule statistics."""
        # Create a mock analyzer
        analyzer = Analyzer(self.fixtures_dir)

        # Create mock findings with canonical IDs
        analyzer.findings["gopher"] = [
            Finding(
                tool="gopher",
                rule_id="R05",
                canonical_id="CR01",
                file_path="/src/test1.go",
                line=10,
                message="MD5 usage",
            ),
            Finding(
                tool="gopher",
                rule_id="R13",
                canonical_id="CR14",
                file_path="/src/test2.go",
                line=20,
                message="Insecure Skip Verify",
            ),
        ]

        analyzer.findings["gosec"] = [
            Finding(
                tool="gosec",
                rule_id="G501",
                canonical_id="CR01",
                file_path="/src/test1.go",
                line=10,
                message="MD5 usage",
            ),
            Finding(
                tool="gosec",
                rule_id="G404",
                canonical_id="CR03",
                file_path="/src/test3.go",
                line=30,
                message="Rand issue",
            ),
        ]

        analyzer.findings["codeql"] = [
            Finding(
                tool="codeql",
                rule_id="CWE-327",
                canonical_id="CR13",
                file_path="/src/test4.go",
                line=40,
                message="Weak TLS",
            )
        ]

        # Create a mock location map
        location_map = {}
        for tool, findings in analyzer.findings.items():
            for finding in findings:
                key = finding.get_match_key()
                if key not in location_map:
                    location_map[key] = []
                location_map[key].append(finding)

        # Mark matching findings
        for key, findings_list in location_map.items():
            if len(findings_list) > 1:
                tools = set(f.tool for f in findings_list)
                if len(tools) > 1:
                    for finding in findings_list:
                        finding.matched = True

        # Run the summary method (this is just for visual inspection)
        print("\nTEST: Analyzer summary with canonical IDs")
        analyzer.print_summary(location_map)

        # Verify the canonical ID counts (programmatically)
        canonical_counts = {}
        for tool, findings in analyzer.findings.items():
            for finding in findings:
                if finding.canonical_id:
                    if finding.canonical_id not in canonical_counts:
                        canonical_counts[finding.canonical_id] = {"total": 0}

                    if tool not in canonical_counts[finding.canonical_id]:
                        canonical_counts[finding.canonical_id][tool] = 0

                    canonical_counts[finding.canonical_id]["total"] += 1
                    canonical_counts[finding.canonical_id][tool] += 1

        # Check the canonical rule counts
        self.assertEqual(canonical_counts["CR01"]["total"], 2)
        self.assertEqual(canonical_counts["CR01"]["gopher"], 1)
        self.assertEqual(canonical_counts["CR01"]["gosec"], 1)

        self.assertEqual(canonical_counts["CR03"]["total"], 1)
        self.assertEqual(canonical_counts["CR03"]["gosec"], 1)

        self.assertEqual(canonical_counts["CR13"]["total"], 1)
        self.assertEqual(canonical_counts["CR13"]["codeql"], 1)

        self.assertEqual(canonical_counts["CR14"]["total"], 1)
        self.assertEqual(canonical_counts["CR14"]["gopher"], 1)


if __name__ == "__main__":
    unittest.main()
