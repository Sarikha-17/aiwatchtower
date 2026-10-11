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

## Public demo safeguards
- **Daily model-call cap** (`MAX_MODEL_CALLS_PER_DAY`): once reached, patch requests use the clearly labeled demo
  fallback (with `DEMO_MODE=true`) instead of calling the paid API. The counter survives demo resets.
- **Reset demo** restores policy v1 and clears runs and patches, because the public demo has no login and all visitors
  share one state. It can be disabled with `ALLOW_DEMO_RESET=false`.
- The `/health` endpoint reports usage and cap but never any secret.
