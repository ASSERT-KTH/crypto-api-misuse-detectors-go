import os
import sys
import unittest
from pathlib import Path

# Add the parent directory to path so we can import analyzer modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Add the src directory to path so we can import tool_consensus modules
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from analyze import Analyzer, Finding


class TestAnalyzer(unittest.TestCase):
    """Test cases for the analyzer functionality."""

    def setUp(self):
        """Set up the test case."""
        # Path to test fixtures
        self.fixtures_dir = Path(__file__).parent / "fixtures" / "test-project"

        # Initialize analyzer
        self.analyzer = Analyzer(self.fixtures_dir)

    def test_load_findings(self):
        """Test loading findings from all tools."""
        # Load findings from all tools
        self.analyzer.load_findings()

        # Check that the expected number of findings were loaded
        self.assertEqual(len(self.analyzer.findings["codeql"]), 1)
        self.assertEqual(len(self.analyzer.findings["gosec"]), 2)
        self.assertEqual(len(self.analyzer.findings["gopher"]), 1)

    def test_compare_findings(self):
        """Test comparing findings across tools."""
        # Load findings
        self.analyzer.load_findings()

        # Compare findings
        location_map = self.analyzer.compare_findings()

        # There should be 2 unique normalized locations
        self.assertEqual(len(location_map), 2)

        # Security.go line 42 should have findings from all 3 tools
        security_key = "src/test/security.go:42"
        self.assertIn(security_key, location_map)
        security_findings = location_map[security_key]

        # There should be 3 findings at this location (from codeql, gosec, and gopher)
        self.assertEqual(len(security_findings), 3)

        # Check that they're from different tools
        tools = set(finding.tool for finding in security_findings)
        self.assertEqual(tools, {"codeql", "gosec", "gopher"})

        # Check that these findings are marked as matched
        for finding in security_findings:
            self.assertTrue(finding.matched)

        # Check the other locations
        crypto_key = "src/test/crypto.go:42"
        self.assertIn(crypto_key, location_map)
        crypto_findings = location_map[crypto_key]

        # There should be 1 finding here (from gosec)
        self.assertEqual(len(crypto_findings), 1)
        self.assertEqual(crypto_findings[0].tool, "gosec")

        # This finding should not be marked as matched
        self.assertFalse(crypto_findings[0].matched)

    def test_path_normalization(self):
        """Test that paths with different prefixes are normalized correctly for matching."""
        # Create findings with different path formats but same actual path
        finding1 = Finding(
            tool="codeql",
            rule_id="CWE-295",
            file_path="/example/path.go",
            line=42,
            message="Test",
        )

        finding2 = Finding(
            tool="gosec",
            rule_id="G402",
            file_path="/analysis/repo/example/path.go",
            line=42,
            message="Test",
        )

        # Test that match keys are the same despite different path formats
        self.assertEqual(finding1.get_match_key(), finding2.get_match_key())

        # Check that the normalized key doesn't have leading slashes
        self.assertEqual(finding1.get_match_key(), "example/path.go:42")


if __name__ == "__main__":
    unittest.main()
