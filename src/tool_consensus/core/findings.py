from dataclasses import dataclass
from typing import Dict, List, Any


@dataclass
class Finding:
    """Normalized representation of a static analysis finding."""

    tool: str
    rule_id: str
    file_path: str
    line: int
    message: str
    severity: str = "unknown"
    column: int = None  # Column number where the finding occurs
    canonical_ids: List[str] = (
        None  # List of canonicalized rule IDs (e.g., [CR01, CR02])
    )
    project_dir: str = (
        ""  # Project directory name (e.g., "github.com-hashicorp-terraform")
    )
    match_key: str = None


    def __post_init__(self):
        """Initialize default values for mutable fields."""
        if self.canonical_ids is None:
            if self.tool in [
                "codeql",
                "gosec",
                "gopher",
            ]:  # exclude snyk since has many irrelevant mappings
                print(
                    f"Warning: Finding for tool {self.tool} has no canonical IDs. This may indicate a missing rule mapping."
                )
            self.canonical_ids = []
        self.normalize_file_path()
        if self.match_key is None:
            self.match_key = self.get_match_key()
        
    def normalize_file_path(self) -> str:
        normalized_path = self.file_path
        if normalized_path.startswith("/analysis/repo/"):
            normalized_path = normalized_path[len("/analysis/repo/") :]
        elif normalized_path.startswith("/"):
            normalized_path = normalized_path[1:]
        self.file_path = normalized_path
        
    def get_match_key(self) -> str:
        """Get a key for comparing findings across tools."""
        # We use project directory, file path and line for matching
        # Include project directory in the key
        if self.project_dir:
            return f"{self.project_dir}/{self.file_path}:{self.line}"
        print(f"Warning: Finding {self} has no project directory set. Using only file path and line.")
        return  f"{self.file_path}:{self.line}"

    def __str__(self) -> str:
        return f"{self.tool} - {self.rule_id} - {self.file_path}:{self.line} - {self.message} ({self.severity})"
