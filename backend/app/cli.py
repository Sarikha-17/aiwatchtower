"""Print every scenario under no firewall / policy v1 / policy v2.  Run: python -m app.cli"""
from app.services.runner import load_scenarios, run_by_id

MODES = [("no firewall", None), ("policy v1", 1), ("policy v2", 2)]


def main() -> None:
    print(f"{'scenario':26}" + "".join(f"{name:32}" for name, _ in MODES))
    for sc in load_scenarios():
        row = f"{sc['scenario_id']:26}"
        for _, version in MODES:
            row += f"{run_by_id(sc['scenario_id'], version).verdict:32}"
        print(row)


if __name__ == "__main__":
    main()
