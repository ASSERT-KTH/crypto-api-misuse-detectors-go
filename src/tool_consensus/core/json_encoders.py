#!/usr/bin/env python3
"""
JSON Encoders for Analysis Objects
"""

import json
from analyze import Finding


class FindingEncoder(json.JSONEncoder):
    """Custom JSON encoder for Finding objects."""

    def default(self, obj):
        if isinstance(obj, Finding):
            return {
                "tool": obj.tool,
                "rule_id": obj.rule_id,
                "file_path": obj.file_path,
                "line": obj.line,
                "message": obj.message,
                "severity": obj.severity,
                "canonical_ids": obj.canonical_ids,
                "line_level_match": obj.line_level_match,
                "alarm_level_match": obj.alarm_level_match,
                "matching_details": obj.matching_details,
            }
        return super().default(obj)
