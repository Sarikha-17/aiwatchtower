# AIWatchTower

Self-hardening governance for AI agents: every security failure becomes a tested, human-approved policy fix.

All data in this repository is fabricated. This is a prototype: it reduces risk through deterministic
tool-call controls, provenance labels, constrained policies, replay testing and human approval. It does
not prevent all prompt injection.

## Run the tests (Windows PowerShell)

    cd backend
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    python -m pytest
