import os
import sys
import unittest
from pathlib import Path

# Add the parent directory to path so we can import analyzer modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Add the src directory to path so we can import tool_consensus modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from analyze import SnykParser, Finding


class TestSnykParser(unittest.TestCase):
    """Test cases for the Snyk parser."""

    def setUp(self):
        """Set up the test case."""
        # Path to test fixtures
        self.fixtures_dir = Path(__file__).parent / "fixtures" / "test-snyk"

        # Initialize parser
        self.snyk_parser = SnykParser()

        # The path to the test Snyk results.json file
        self.snyk_file = self.fixtures_dir / "snyk" / "results.json"

    def test_snyk_parser_loads_mappings(self):
        """Test that the Snyk parser correctly loads the rule mappings."""
        # Verify mappings were loaded
        self.assertTrue(self.snyk_parser.canonicalized_mappings)
        self.assertTrue(self.snyk_parser.snyk_to_canonical)

        # Test specific mappings
        # InsecureCipher should map to CR01 and CR02
        self.assertIn("CR01", self.snyk_parser.get_canonical_ids("go/InsecureCipher"))
        self.assertIn("CR02", self.snyk_parser.get_canonical_ids("go/InsecureCipher"))

        # TooPermissiveTrustManager should map to CR14
        self.assertIn(
            "CR14", self.snyk_parser.get_canonical_ids("go/TooPermissiveTrustManager")
        )

        # InsecureTLSConfig should map to CR12
        self.assertIn(
            "CR12", self.snyk_parser.get_canonical_ids("go/InsecureTLSConfig")
        )

        # InsecureHash should map to CR10
        self.assertIn("CR10", self.snyk_parser.get_canonical_ids("go/InsecureHash"))

    def test_snyk_parse_file(self):
        """Test that the Snyk parser correctly parses the results file."""
        # Parse the test file
        findings = self.snyk_parser.parse_file(self.snyk_file)

        # Should only find 4 relevant findings (HardcodedPassword is not in our mappings)
        self.assertEqual(len(findings), 4)

        # Verify findings details
        finding_by_rule = {finding.rule_id: finding for finding in findings}

        # Check InsecureCipher finding
        insecure_cipher = finding_by_rule.get("go/InsecureCipher")
        self.assertIsNotNone(insecure_cipher)
        self.assertEqual(insecure_cipher.file_path, "src/crypto.go")
        self.assertEqual(insecure_cipher.line, 15)
        self.assertEqual(
            insecure_cipher.message, "Using insecure cipher in crypto operations."
        )
        self.assertEqual(insecure_cipher.severity, "high")  # error maps to high
        self.assertIn("CR01", insecure_cipher.canonical_ids)
        self.assertIn("CR02", insecure_cipher.canonical_ids)

        # Check TooPermissiveTrustManager finding
        trust_manager = finding_by_rule.get("go/TooPermissiveTrustManager")
        self.assertIsNotNone(trust_manager)
        self.assertEqual(trust_manager.file_path, "src/tls.go")
        self.assertEqual(trust_manager.line, 25)
        self.assertEqual(trust_manager.severity, "medium")  # warning maps to medium
        self.assertIn("CR14", trust_manager.canonical_ids)

        # Check InsecureTLSConfig finding
        tls_config = finding_by_rule.get("go/InsecureTLSConfig")
        self.assertIsNotNone(tls_config)
        self.assertEqual(tls_config.file_path, "src/tls_config.go")
        self.assertEqual(tls_config.line, 30)
        self.assertEqual(tls_config.severity, "high")  # error maps to high
        self.assertIn("CR12", tls_config.canonical_ids)

        # Check InsecureHash finding
        insecure_hash = finding_by_rule.get("go/InsecureHash")
        self.assertIsNotNone(insecure_hash)
        self.assertEqual(insecure_hash.file_path, "src/password.go")
        self.assertEqual(insecure_hash.line, 55)
        self.assertEqual(insecure_hash.severity, "medium")  # warning maps to medium
        self.assertIn("CR10", insecure_hash.canonical_ids)

        # Verify HardcodedPassword is not in the findings (not mapped to canonical ID)
        self.assertNotIn("go/HardcodedPassword/test", finding_by_rule)

    def test_snyk_empty_file(self):
        """Test that the Snyk parser handles empty files gracefully."""
        # Create an empty file
        empty_file = self.fixtures_dir / "snyk" / "empty.json"
        with open(empty_file, "w") as f:
            f.write("")

        # Parse the empty file
        findings = self.snyk_parser.parse_file(empty_file)
        self.assertEqual(len(findings), 0)

        # Cleanup
        empty_file.unlink()

    def test_snyk_invalid_json(self):
        """Test that the Snyk parser handles invalid JSON gracefully."""
        # Create an invalid JSON file
        invalid_file = self.fixtures_dir / "snyk" / "invalid.json"
        with open(invalid_file, "w") as f:
            f.write("{this is not valid json")

        # Parse the invalid file
        findings = self.snyk_parser.parse_file(invalid_file)
        self.assertEqual(len(findings), 0)

        # Cleanup
        invalid_file.unlink()

    def test_snyk_missing_runs(self):
        """Test that the Snyk parser handles files with missing runs gracefully."""
        # Create a file with missing runs
        missing_runs_file = self.fixtures_dir / "snyk" / "missing_runs.json"
        with open(missing_runs_file, "w") as f:
            f.write('{"version": "2.1.0", "no_runs": []}')

        # Parse the file
        findings = self.snyk_parser.parse_file(missing_runs_file)
        self.assertEqual(len(findings), 0)

        # Cleanup
        missing_runs_file.unlink()


if __name__ == "__main__":
    unittest.main()
