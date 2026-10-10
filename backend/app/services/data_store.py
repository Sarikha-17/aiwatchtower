"""Loads the fake emails and HR files. All data is fabricated."""
import json
from dataclasses import dataclass
from pathlib import Path

from app.config import DATA_DIR


@dataclass
class DataStore:
    emails: dict
    hr_files: dict

    @classmethod
    def from_files(cls, data_dir: Path | None = None) -> "DataStore":
        data_dir = data_dir or DATA_DIR
        emails = json.loads((data_dir / "emails.json").read_text(encoding="utf-8"))
        files = json.loads((data_dir / "hr_files.json").read_text(encoding="utf-8"))
        return cls(
            emails={e["email_id"]: e for e in emails},
            hr_files={f["file_id"]: f for f in files},
        )
