"""Loads the fake emails and HR files. All data is fabricated."""
import json
from dataclasses import dataclass
from pathlib import Path

from app.config import DATA_DIR


@dataclass
class DataStore:
    emails: dict
    hr_files: dict

    def with_finance(self, data_dir: Path | None = None) -> "DataStore":
        """Copy of this store plus the fabricated finance files. Only finance cases use it, so the file
        catalogue shown to the agent (and the model-call cache keys) for every older case is unchanged."""
        data_dir = data_dir or DATA_DIR
        files = json.loads((data_dir / "finance_files.json").read_text(encoding="utf-8"))
        return DataStore(emails=dict(self.emails), hr_files={**self.hr_files, **{f["file_id"]: f for f in files}})

    @classmethod
    def from_files(cls, data_dir: Path | None = None) -> "DataStore":
        data_dir = data_dir or DATA_DIR
        emails = json.loads((data_dir / "emails.json").read_text(encoding="utf-8"))
        files = json.loads((data_dir / "hr_files.json").read_text(encoding="utf-8"))
        return cls(
            emails={e["email_id"]: e for e in emails},
            hr_files={f["file_id"]: f for f in files},
        )
