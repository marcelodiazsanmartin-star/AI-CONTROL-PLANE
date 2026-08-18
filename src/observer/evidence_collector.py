"""
Evidence Collector Module (Read-Only)

Safely collects and parses evidence files from monitored repositories.
Calculates file modification timestamps and freshness without touching or writing to target files.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from src.contracts import EvidenceItem


class EvidenceCollector:
    def __init__(self, reference_time: Optional[datetime] = None):
        """
        :param reference_time: Optional UTC datetime override for clock skew / test scenarios.
        """
        self.reference_time = reference_time

    def get_current_time(self) -> datetime:
        return self.reference_time or datetime.now(timezone.utc)

    def collect_file_evidence(self, base_path: Path, relative_filepath: str) -> EvidenceItem:
        full_path = base_path / relative_filepath
        source_name = Path(relative_filepath).name

        if not full_path.exists():
            return EvidenceItem(
                source_name=source_name,
                filepath=str(full_path),
                file_exists=False,
                parse_error="File does not exist"
            )

        try:
            mtime = full_path.stat().st_mtime
            mtime_dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
            now_dt = self.get_current_time()
            age_seconds = (now_dt - mtime_dt).total_seconds()

            # Read-only open
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()

            parsed_data = None
            parse_error = None

            if full_path.suffix.lower() == ".json":
                try:
                    parsed_data = json.loads(content)
                except json.JSONDecodeError as jde:
                    parse_error = f"JSON decode error: {str(jde)}"
            else:
                parsed_data = {"raw_text": content}

            return EvidenceItem(
                source_name=source_name,
                filepath=str(full_path),
                file_exists=True,
                last_modified_iso=mtime_dt.isoformat(),
                age_seconds=max(0.0, age_seconds),
                parsed_data=parsed_data,
                parse_error=parse_error
            )

        except Exception as e:
            return EvidenceItem(
                source_name=source_name,
                filepath=str(full_path),
                file_exists=True,
                parse_error=f"Error reading file: {str(e)}"
            )

    def collect_project_evidence(self, base_path: Path, relative_filepaths: List[str]) -> Dict[str, EvidenceItem]:
        results = {}
        for rel_path in relative_filepaths:
            item = self.collect_file_evidence(base_path, rel_path)
            results[rel_path] = item
        return results
