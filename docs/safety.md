# Safety

- **Fabricated data only.** Employees, salaries, files, emails and domains (`*.example`) are invented.
- **Sandbox only.** Attacks run inside the local sandbox against a scripted agent. `email.send` records a message in a
  local outbox and never sends anything. No third-party system is attacked.
- **Human in the loop.** A patch never activates automatically. Approval needs a passing validation and replay
  evidence; rejection stores a reason; rollback restores a prior version; every action is logged.
- **Models advise, code decides.** A model cannot approve an action that violates a deterministic rule, cannot
  decide whether an attack succeeded, and cannot change code, models, prompts, tools or permissions through a patch.
- **Secrets.** API keys live in `.env` (git-ignored) and are never logged or returned by the API.
- **Not a certification.** This prototype is not legal DPDP compliance advice or certification.
- **No guarantee.** It reduces risk; it does not prevent all prompt injection.
