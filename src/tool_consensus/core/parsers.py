from pathlib import Path
import json
import sys
from typing import Dict, List, Any
from core.findings import Finding
import csv


class BaseParser:
    """Base class for all parsers with shared functionality."""

    def __init__(
        self, project_dir: str = "", canonicalized_mappings: List[Dict[str, Any]] = None
    ):
        """Initialize parser with project directory name and canonicalized mappings.

        Args:
            project_dir: Name of the project directory (e.g., "github.com-hashicorp-terraform")
            canonicalized_mappings: List of canonicalized rule mappings
        """
        self.project_dir = project_dir
        self.canonicalized_mappings = canonicalized_mappings or []


class CodeQLParser(BaseParser):
    """Parser for CodeQL CSV output."""

    def __init__(
        self, project_dir: str = "", canonicalized_mappings: List[Dict[str, Any]] = None
    ):
        """Initialize parser with project directory name."""
        super().__init__(project_dir, canonicalized_mappings)
        self.codeql_to_canonical = self._build_reverse_mapping()

    def _build_reverse_mapping(self) -> Dict[str, List[str]]:
        """Build a mapping from CodeQL rule IDs to lists of canonicalized rule IDs."""
        codeql_to_canonical = {}
        for rule in self.canonicalized_mappings:
            canonical_id = rule.get("id")
            codeql_ids = rule.get("codeql", [])
            for codeql_id in codeql_ids:
                if codeql_id not in codeql_to_canonical:
                    codeql_to_canonical[codeql_id] = []
                codeql_to_canonical[codeql_id].append(canonical_id)
        return codeql_to_canonical

    def get_canonical_ids(self, codeql_id: str) -> List[str]:
        """Get all canonicalized rule IDs for a CodeQL rule ID."""
        return self.codeql_to_canonical.get(codeql_id, [])

    def parse_directory(self, directory: Path) -> List[Finding]:
        """Parse all CodeQL CSV files in the given directory."""
        findings = []

        for csv_file in directory.glob("*.csv"):
            findings.extend(self._parse_csv(csv_file))

        return findings

    def _parse_csv(self, csv_file: Path) -> List[Finding]:
        """Parse a single CodeQL CSV file."""
        findings = []
        rule_id = csv_file.stem.split("_")[0]  # Use CWE ID as rule ID
        canonical_ids = self.get_canonical_ids(rule_id)

        if not canonical_ids:
            if rule_id != "CWE-798":  # post analysis removed
                print(f"Warning: No canonical IDs found for rule {rule_id} in CodeQL output")
        else:
            with open(csv_file, "r", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:  # get all detections in the CSV file
                    try:
                        finding = Finding(
                            tool="codeql",
                            rule_id=rule_id,
                            file_path=row.get("Path", ""),
                            line=int(row.get("Start line", 0)),
                            message=row.get("Message", ""),
                            severity=row.get("Severity", "unknown"),
                            column=row.get("Start column", None),
                            canonical_ids=canonical_ids.copy(),  # Use all matching canonical IDs
                            project_dir=self.project_dir,
                            match_key=None,
                        )
                        findings.append(finding)
                    except (KeyError, ValueError) as e:
                        print(
                            f"Error parsing CodeQL finding: {e}, row: {row}",
                            file=sys.stderr,
                        )

        return findings


class GosecParser(BaseParser):
    """Parser for Gosec JSON output."""

    def __init__(
        self, project_dir: str = "", canonicalized_mappings: List[Dict[str, Any]] = None
    ):
        """Initialize parser with project directory name."""
        super().__init__(project_dir, canonicalized_mappings)
        self.gosec_to_canonical = self._build_reverse_mapping()

    def _build_reverse_mapping(self) -> Dict[str, List[str]]:
        """Build a mapping from Gosec rule IDs to lists of canonicalized rule IDs."""
        gosec_to_canonical = {}
        for rule in self.canonicalized_mappings:
            canonical_id = rule.get("id")
            gosec_ids = rule.get("gosec", [])
            for gosec_id in gosec_ids:
                if gosec_id not in gosec_to_canonical:
                    gosec_to_canonical[gosec_id] = []
                gosec_to_canonical[gosec_id].append(canonical_id)
        return gosec_to_canonical

    def get_canonical_ids(self, gosec_id: str) -> List[str]:
        """Get all canonicalized rule IDs for a Gosec rule ID."""
        return self.gosec_to_canonical.get(gosec_id, [])

    def parse_file(self, json_file: Path) -> List[Finding]:
        """Parse the Gosec results.json file."""
        findings = []

        try:
            # Check if file is empty or has minimal content
            file_size = json_file.stat().st_size
            if file_size < 5:  # Too small to be valid JSON
                return findings

            with open(json_file, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    print(f"Error parsing Gosec JSON: {json_file}", file=sys.stderr)
                    return findings

            for issue in data.get("Issues", []):
                file_path = issue.get("file", "")
                line_str = issue.get("line", "0")
                column_str = issue.get("column", "0")

                # Handle line ranges like "55-57" by taking the first number
                if isinstance(line_str, str) and "-" in line_str:
                    # print(f"found line range in gosec: {line_str}")
                    line_str = line_str.split("-")[0]  # use start line

                try:
                    line = int(line_str)
                except (ValueError, TypeError):
                    line = 0

                try:
                    column = int(column_str)
                except (ValueError, TypeError):
                    column = None

                rule_id = issue.get("rule_id", "")
                canonical_ids = self.get_canonical_ids(rule_id)

                if not canonical_ids:
                    if rule_id != "G504":  # post analysis removal: irrelevant alarm
                        print(
                            f"Warning: No canonical IDs found for rule {rule_id} in Gosec output"
                        )
                    continue  # Skip findings that don't map to any canonical rule

                finding = Finding(
                    tool="gosec",
                    rule_id=rule_id,
                    file_path=file_path,
                    line=line,
                    message=issue.get("details", ""),
                    severity=issue.get("severity", "unknown"),
                    column=column,
                    canonical_ids=canonical_ids.copy(),  # Use all matching canonical IDs
                    project_dir=self.project_dir,
                    match_key=None,
                )
                findings.append(finding)

        except (KeyError, ValueError, OSError) as e:
            print(f"Error parsing Gosec results: {e}", file=sys.stderr)

        return findings


class SnykParser(BaseParser):
    """Parser for Snyk JSON output."""

    def __init__(
        self, project_dir: str = "", canonicalized_mappings: List[Dict[str, Any]] = None
    ):
        """Initialize parser with project directory name."""
        super().__init__(project_dir, canonicalized_mappings)
        self.snyk_to_canonical = self._build_reverse_mapping()

    def _build_reverse_mapping(self) -> Dict[str, List[str]]:
        """Build a mapping from Snyk rule IDs to lists of canonicalized rule IDs."""
        snyk_to_canonical = {}
        for rule in self.canonicalized_mappings:
            canonical_id = rule.get("id")
            snyk_ids = rule.get("snyk", [])
            for snyk_id in snyk_ids:
                if snyk_id not in snyk_to_canonical:
                    snyk_to_canonical[snyk_id] = []
                snyk_to_canonical[snyk_id].append(canonical_id)
        return snyk_to_canonical

    def get_canonical_ids(self, snyk_id: str) -> List[str]:
        """Get all canonicalized rule IDs for a Snyk rule ID."""
        return self.snyk_to_canonical.get(snyk_id, [])

    def parse_file(self, json_file: Path) -> List[Finding]:
        """Parse the Snyk results.json file in SARIF format."""
        findings = []

        try:
            # Check if file is empty or has minimal content
            file_size = json_file.stat().st_size
            if file_size < 5:  # Too small to be valid JSON
                return findings

            with open(json_file, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    print(f"Error parsing Snyk JSON: {json_file}", file=sys.stderr)
                    return findings

            # Process Snyk SARIF format
            # The results are in data["runs"][0]["results"]
            if "runs" not in data or not data["runs"]:
                results_list = data.get("results")
                if isinstance(results_list, list):
                    if results_list:
                        print(
                            f"Unsupported Snyk results format (non-empty 'results' without 'runs'): {json_file}",
                            file=sys.stderr,
                        )
                    return findings
                print(
                    f"No 'runs' found in Snyk SARIF data: {json_file}",
                    file=sys.stderr,
                )
                return findings

            run = data["runs"][0]  # Get the first run
            if "results" not in run:
                print(
                    f"No 'results' found in Snyk SARIF run: {json_file}",
                    file=sys.stderr,
                )
                return findings

            for result in run["results"]:
                rule_id = result.get("ruleId", "")

                # Only process findings that map to canonical rules
                canonical_ids = self.get_canonical_ids(rule_id)

                if not canonical_ids:
                    continue  # Skip findings that don't map to any canonical rule

                # Get severity
                severity = "unknown"
                if "level" in result:
                    severity_map = {
                        "error": "high",
                        "warning": "medium",
                        "note": "low",
                        "none": "info",
                    }
                    severity = severity_map.get(result["level"], "unknown")

                # Get message
                message = ""
                if "message" in result:
                    if isinstance(result["message"], dict):
                        message = result["message"].get("text", "")
                    elif isinstance(result["message"], str):
                        message = result["message"]

                # Get file location, line and column
                file_path = ""
                line = 0
                column = None
                if "locations" in result and result["locations"]:
                    location = result["locations"][0]  # Use the first location
                    if "physicalLocation" in location:
                        physical = location["physicalLocation"]
                        if "artifactLocation" in physical:
                            file_path = physical["artifactLocation"].get("uri", "")

                        if "region" in physical:
                            line = physical["region"].get("startLine", 0)
                            column = physical["region"].get("startColumn", None)

                finding = Finding(
                    tool="snyk",
                    rule_id=rule_id,
                    file_path=file_path,
                    line=line,
                    message=message,
                    severity=severity,
                    column=column,
                    canonical_ids=canonical_ids.copy(),  # Use all matching canonical IDs
                    project_dir=self.project_dir,
                    match_key=None,
                )
                findings.append(finding)

        except (KeyError, ValueError, OSError) as e:
            print(f"Error parsing Snyk results: {e}", file=sys.stderr)

        return findings


class GopherParser(BaseParser):
    """Parser for Gopher JSON output."""

    def __init__(
        self, project_dir: str = "", canonicalized_mappings: List[Dict[str, Any]] = None
    ):
        """Initialize parser with project directory name."""
        super().__init__(project_dir, canonicalized_mappings)
        self.gopher_to_canonical = self._build_reverse_mapping()

        # Mapping rules based on message patterns and predicate types
        # These mappings are used to identify specific Gopher rules
        self.message_patterns = {
            # R05 - Dangerous algorithms
            "MD5": "R05",
            "MD4": "R05",
            "SHA-1": "R05",
            "RIPEMD-160": "R05",
            "RC4": "R05",
            "Blowfish": "R05",
            "TEA": "R05",
            "XTEA": "R05",
            "PKCS1V1.5": "R05",
            # R06 - Warning algorithms
            "3DES is aceptable but not recommended": "R06",
            "SHA-224": "R06",
            "SHA2-224": "R06",
            "SHA2-512/224": "R06",
            "SHA3-224": "R06",
            "HMAC-MD5": "R06",
            "P224": "R06",
            "DSA-2048 is Acceptable but not recommended": "R06",
            "RSA-2048 is Acceptable but not recommended": "R06",
            # R07-R11 - Randomness/Predictability issues
            "AES-key should be random": "R09",
            "HMAC-key should be random": "R09",
            "Salt should be random": "R08",
            "IV should be unique in GCM mode": "R11",
            # R12-R18 - TLS/SSH/HTTPS issues
            "HTTP connection is very dangerous": "R12",
            "Insecure Verification": "R13",
            "InsecureIgnoreHostKey": "R14",
            "The TLS suite can be customized": "R15",
            "Insecure TLS Version": "R17",
            "The SSH suite can be customized": "R18",
            # R01-R04 - Parameter issues
            "The length of the key should be at least": "R02",
            "In 2023, OWASP recommended to use": "R04",
            "The cost should be greater than": "R04",
            "owasp recommended parameters is": "R04",
            "salt length": "R01",
            # R19 - Deprecated functions
            "Deprecated: ": "R19",
            "Deprecated:": "R19",
            "is deprecated": "R19",
        }

        # Mapping based on predicate types
        self.predicate_mapping = {
            "BYTE_LENGTH": ["R01", "R02"],  # Need to check message for specifics
            "GEQ": ["R03", "R04", "R17"],  # Need to check message for specifics
            "HTTPS": "R12",
            "EQ_FALSE": ["R13", "R14"],  # Need to check message for specifics
            "RANDOM_BYTES": [
                "R08",
                "R09",
                "R10",
            ],  # Need to check message for specifics
            "NOT_CONST": "R11",
            "RANDOM_IO": "R07",
            "SECURE_TLS_SUITE": [
                "R15",
                "R16",
                "R17",
            ],  # Need to check message for specifics
            "SECURE_SSH_SUITE": "R18",
            "Dangerous_Function": "R05",
            "Warning_Function": "R06",
        }

        # Mapping for function names (fallback)
        self.function_name_mapping = {
            # Dangerous algorithms - R05
            "crypto/md5": "R05",
            "crypto/md4": "R05",
            "crypto/sha1": "R05",
            "crypto/des": "R05",
            "crypto/rc4": "R05",
            "crypto/blowfish": "R05",
            "crypto/tea": "R05",
            "crypto/xtea": "R05",
            # Warning algorithms - R06
            "crypto/sha224": "R06",
            "elliptic.P224": "R06",
            "crypto/sha512.Sum224": "R06",
            "crypto/sha3.Sum224": "R06",
            "crypto/hmac.New(md5.New": "R06",
            # Deprecated functions - R19 (previously also mapped to R05)
            "crypto/rsa.EncryptPKCS1v15": "R19",
            # Verification issues
            "crypto/tls.Config.InsecureSkipVerify": "R13",
            "crypto/ssh.InsecureIgnoreHostKey": "R14",
        }

    def _map_to_rule_id(self, finding_obj):
        """Map a finding to a rule ID based on patterns in the message and predicate type."""
        message = finding_obj.get("Message", "")
        predicate_type = finding_obj.get("Predicate_Type", "")
        func_name = finding_obj.get("FuncName", "")

        # First try to match based on message patterns
        for pattern, rule_id in self.message_patterns.items():
            if pattern in message:
                return rule_id

        # If no match in message, try predicate type
        if predicate_type in self.predicate_mapping:
            mapping = self.predicate_mapping[predicate_type]

            # If predicate maps to multiple possible rules, try to determine which one
            if isinstance(mapping, list):
                # Byte length related
                if predicate_type == "BYTE_LENGTH":
                    if "salt" in message.lower() or "salt" in func_name.lower():
                        return "R01"
                    else:
                        return "R02"  # Key length

                # Parameter scale related
                elif predicate_type == "GEQ":
                    if "TLS" in message or "tls" in func_name.lower():
                        return "R17"  # TLS version
                    elif "RSA" in message or "DSA" in message:
                        return "R03"  # Key size
                    else:
                        return "R04"  # Iteration count

                # Randomness related
                elif predicate_type == "RANDOM_BYTES":
                    if "salt" in message.lower():
                        return "R08"  # Salt randomness
                    elif "IV" in message or "iv" in message.lower():
                        return "R10"  # IV randomness
                    else:
                        return "R09"  # Key randomness

                # TLS/SSL related
                elif predicate_type == "SECURE_TLS_SUITE":
                    if "version" in message.lower():
                        return "R17"  # TLS version
                    elif "signature" in message.lower():
                        return "R16"  # Signature algorithm
                    else:
                        return "R15"  # TLS suite

                # Verification related
                elif predicate_type == "EQ_FALSE":
                    if "SSH" in message or "ssh" in func_name.lower():
                        return "R14"  # SSH verification
                    else:
                        return "R13"  # TLS verification
            else:
                return mapping

        # Last resort: check function name for clues
        for func_pattern, rule_id in self.function_name_mapping.items():
            if func_pattern in func_name:
                return rule_id

        # If all else fails, use a default
        if "Dangerous_Function" in predicate_type:
            return "R05"
        elif "Warning_Function" in predicate_type:
            return "R06"

        # Truly unknown
        print(f"\n\nWARNING: Gopher rule ID not found for finding: {finding_obj}\n\n")
        return "R99"  # Unknown/unclassified

    def _build_reverse_mapping(self) -> Dict[str, List[str]]:
        """Build a mapping from Gopher rule IDs to lists of canonicalized rule IDs."""
        gopher_to_canonical = {}
        for rule in self.canonicalized_mappings:
            canonical_id = rule.get("id")
            gopher_ids = rule.get("gopher", [])
            for gopher_id in gopher_ids:
                if gopher_id not in gopher_to_canonical:
                    gopher_to_canonical[gopher_id] = []
                gopher_to_canonical[gopher_id].append(canonical_id)
        return gopher_to_canonical

    def get_canonical_ids(self, gopher_id: str) -> List[str]:
        """Get all canonicalized rule IDs for a Gopher rule ID."""
        return self.gopher_to_canonical.get(gopher_id, [])

    def parse_file(self, json_file: Path) -> List[Finding]:
        """Parse the Gopher results.json file."""
        findings = []

        try:
            with open(json_file, "r") as f:
                data = json.load(f)

            # Based on the actual Gopher output structure
            for finding_obj in data:
                slicing_criteria = finding_obj.get("Slicing_Criteria", {})
                file_path = slicing_criteria.get("SourceFilename", "")
                line = slicing_criteria.get("SourceLineNum", 0)

                # Map to appropriate rule ID
                rule_id = self._map_to_rule_id(finding_obj)

                # Get the canonical rule IDs
                canonical_ids = self.get_canonical_ids(rule_id)

                if not canonical_ids:
                    print(
                        f"Warning: No canonical IDs found for rule {rule_id} in Gopher output"
                    )
                    continue  # Skip findings that don't map to any canonical rule

                # Map severity based on rule ID (from the CSV)
                severity_map = {
                    "R01": "low",
                    "R02": "low",
                    "R03": "low",
                    "R04": "low",
                    "R05": "high",
                    "R06": "low",
                    "R07": "medium",
                    "R08": "low",
                    "R09": "high",
                    "R10": "medium",
                    "R11": "medium",
                    "R12": "high",
                    "R13": "high",
                    "R14": "high",
                    "R15": "high",
                    "R16": "high",
                    "R17": "high",
                    "R18": "high",
                    "R19": "low",
                }
                severity = severity_map.get(rule_id, "unknown")

                finding = Finding(
                    tool="gopher",
                    rule_id=rule_id,
                    file_path=file_path,
                    line=int(line) if line else 0,
                    message=finding_obj.get("Message", ""),
                    severity=severity,
                    column=None,  # Gopher doesn't provide column information
                    canonical_ids=canonical_ids.copy(),  # Use all matching canonical IDs
                    project_dir=self.project_dir,
                    match_key=None,
                )
                findings.append(finding)

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"Error parsing Gopher results: {e}", file=sys.stderr)

        return findings
