"""Static datasets. Held-out attacks live in their own file and are never shown to the patcher."""
import json
from pathlib import Path

from app.config import DATA_DIR

TRAIN, HELD_OUT, LEGIT = "train_attack", "held_out_attack", "legitimate"


def _load(name: str, data_dir: Path | None = None) -> list:
    return json.loads(((data_dir or DATA_DIR) / name).read_text(encoding="utf-8"))


def load_train_attacks(data_dir=None) -> list:
    return _load("train_attacks.json", data_dir)


def load_held_out_attacks(data_dir=None) -> list:
    return _load("held_out_attacks.json", data_dir)


def load_legitimate_tasks(data_dir=None) -> list:
    return _load("legitimate_tasks.json", data_dir)


def load_all_cases(data_dir=None) -> list:
    return load_train_attacks(data_dir) + load_held_out_attacks(data_dir) + load_legitimate_tasks(data_dir)


def patcher_visible_cases(data_dir=None) -> list:
    """Everything the patcher prompt may draw from. Held-out attacks are excluded by construction."""
    return load_train_attacks(data_dir) + load_legitimate_tasks(data_dir)


def case_to_scenario(case: dict) -> dict:
    """Turn a stored case (a recorded sequence of proposed tool calls) into a replayable scenario."""
    return {
        "scenario_id": case["case_id"],
        "kind": "attack" if case["kind"] in (TRAIN, HELD_OUT) else "legit",
        "user_request": case["user_request"],
        "email_id": case["email"]["email_id"] if case.get("email") else None,
        "extra_calls": case["calls"],
    }
