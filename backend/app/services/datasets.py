"""Static datasets. Held-out attacks live in their own file and are never shown to the patcher."""
import json
from pathlib import Path

from app.config import DATA_DIR

TRAIN, HELD_OUT, LEGIT = "train_attack", "held_out_attack", "legitimate"


def _load(name: str, data_dir: Path | None = None) -> list:
    return json.loads(((data_dir or DATA_DIR) / name).read_text(encoding="utf-8"))


def load_train_attacks(data_dir=None) -> list:
    return _load("train_attacks.json", data_dir)


def load_realistic_attacks(data_dir=None) -> list:
    """Disguised business-request attacks, used for the real-agent evaluation (still TRAINING-type, never held-out)."""
    return _load("train_attacks_realistic.json", data_dir)
def load_new_attacks(data_dir=None) -> list:
    """Second batch of disguised attacks (development set, not held-out)."""
    return _load("train_attacks_new.json", data_dir)
def load_struct_attacks(data_dir=None) -> list:
    return _load("train_attacks_struct.json", data_dir)


def load_new_legit_tasks(data_dir=None) -> list:
    return _load("legitimate_tasks_new.json", data_dir)

def load_held_out_attacks(data_dir=None) -> list:
    return _load("held_out_attacks.json", data_dir)


def load_legitimate_tasks(data_dir=None) -> list:
    return _load("legitimate_tasks.json", data_dir)


def load_all_cases(data_dir=None) -> list:
    return load_train_attacks(data_dir) + load_held_out_attacks(data_dir) + load_legitimate_tasks(data_dir)


def patcher_visible_cases(data_dir=None) -> list:
    """Everything the patcher prompt may draw from. Held-out attacks are excluded by construction."""
    return load_train_attacks(data_dir) + load_realistic_attacks(data_dir) + load_legitimate_tasks(data_dir)


def case_to_scenario(case: dict) -> dict:
    """Turn a stored case (a recorded sequence of proposed tool calls) into a replayable scenario."""
    return {
        "scenario_id": case["case_id"],
        "kind": "attack" if case["kind"] in (TRAIN, HELD_OUT) else "legit",
        "user_request": case["user_request"],
        "email_id": case["email"]["email_id"] if case.get("email") else None,
        "extra_calls": case["calls"],
    }
def load_body_attacks(data_dir=None) -> list:
      return _load("train_attacks_body.json", data_dir)

def load_blind_attacks(data_dir=None):
       return _load("train_attacks_blind.json", data_dir)

def load_share_attacks(data_dir=None) -> list:
    return _load("train_attacks_share.json", data_dir)


def load_share_legit_tasks(data_dir=None) -> list:
    return _load("legitimate_tasks_share.json", data_dir)


def load_finance_attacks(data_dir=None) -> list:
    return _load("train_attacks_finance.json", data_dir)


def load_finance_legit_tasks(data_dir=None) -> list:
    return _load("legitimate_tasks_finance.json", data_dir)


def load_named_attacks(data_dir=None):
       return _load("train_attacks_named.json", data_dir)