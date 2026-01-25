import os
import sys
import unittest
from pathlib import Path

# Add the parent directory to path so we can import analyzer modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Add the src directory to path so we can import tool_consensus modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from analyze import CodeQLParser, GosecParser, GopherParser


class TestParsers(unittest.TestCase):
    """Test cases for the individual parsers."""

    def setUp(self):
        """Set up the test case."""
        # Path to test fixtures
        self.fixtures_dir = Path(__file__).parent / "fixtures" / "test-project"

        # Initialize parsers
        self.codeql_parser = CodeQLParser()
        self.gosec_parser = GosecParser()
        self.gopher_parser = GopherParser()

    def test_codeql_parser(self):
        """Test parsing CodeQL CSV output."""
        codeql_dir = self.fixtures_dir / "codeql"
        findings = self.codeql_parser.parse_directory(codeql_dir)

        # Check that we found the expected finding
        self.assertEqual(len(findings), 1)
        finding = findings[0]

        # Check finding attributes
        self.assertEqual(finding.tool, "codeql")
        self.assertEqual(finding.rule_id, "CWE-327")
        self.assertEqual(finding.file_path, "/src/test/security.go")
        self.assertEqual(finding.line, 42)
        self.assertEqual(finding.severity, "warning")
        self.assertIn("Use of an insecure cipher suite", finding.message)

    def test_gosec_parser(self):
        """Test parsing Gosec JSON output."""
        gosec_file = self.fixtures_dir / "gosec" / "results.json"
        findings = self.gosec_parser.parse_file(gosec_file)

        # Check that we found the expected findings
        self.assertEqual(len(findings), 2)

        # Check the first finding
        finding1 = findings[0]
        self.assertEqual(finding1.tool, "gosec")
        self.assertEqual(finding1.rule_id, "G501")
        self.assertEqual(finding1.file_path, "/src/test/crypto.go")
        self.assertEqual(finding1.line, 42)
        self.assertEqual(finding1.severity, "HIGH")
        self.assertIn("Blocklisted import crypto/md5", finding1.message)

        # Check the second finding
        finding2 = findings[1]
        self.assertEqual(finding2.tool, "gosec")
        self.assertEqual(finding2.rule_id, "G401")
        self.assertEqual(finding2.file_path, "/src/test/security.go")
        self.assertEqual(finding2.line, 42)
        self.assertEqual(finding2.severity, "HIGH")
        self.assertIn("Use of weak cryptographic primitive", finding2.message)

    def test_gopher_parser(self):
        """Test parsing Gopher JSON output."""
        gopher_file = self.fixtures_dir / "gopher" / "results.json"
        findings = self.gopher_parser.parse_file(gopher_file)

        # Check that we found the expected finding
        self.assertEqual(len(findings), 1)
        finding = findings[0]

        # Check finding attributes
        self.assertEqual(finding.tool, "gopher")
        self.assertEqual(finding.rule_id, "R05")
        self.assertEqual(finding.file_path, "/src/test/security.go")
        self.assertEqual(finding.line, 42)
        self.assertEqual(finding.severity, "high")  # R05 severity is 'high'
        self.assertIn("MD5 - RFC 9155", finding.message)


if __name__ == "__main__":
    unittest.main()
