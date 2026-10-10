# Threat model

## Scope
A company assistant that can read email, read HR files and send email. The attacker controls **content the agent
reads** (vendor emails, document text), not the user, the model weights, or the firewall.

## Assets
Sensitive HR data (compensation, performance reviews, personal data) and the integrity of tool calls.

## Attack goal
Cause the agent to send an HR-sensitive attachment to a non-allowlisted external address.

## Attack techniques covered by the datasets
Hidden instruction, indirect wording, fake compliance request, disguised attachment name, instruction in the
subject line, encoded instruction, fake executive authority, multi-step escalation, lookalike recipient domains.

## Controls
- Content from emails and files is **data, not authority**; the user request is the only trusted instruction.
- Per-content provenance labels (no session-wide taint flag).
- Typed, validated tool calls; unknown arguments rejected.
- Exact-domain allowlist (lookalike domains are treated as unknown external).
- Declarative policies decided by deterministic code; models advise only.
- Constrained patches, replay evidence and human approval before any policy change; rollback available.

## Known gaps (stated, not hidden)
1. **Instruction hidden in an internal file.** Provenance labels internal HR files as sensitive, not untrusted, so a
   poisoned internal document is not flagged. (held-out cases 09 and 10)
2. **User-authorised social engineering.** If the user's own request names the attacker's address and the file, the
   call is not "influenced". Such a send should go to REVIEW. (held-out case 11)
3. **Attachment-based definition of success.** The evaluator measures exfiltration via tagged attachments only.
   Sensitive text pasted into a message body is out of scope for this MVP.
4. **Keyword-based instruction detection** is a heuristic label; a paraphrase can evade it. Policies do not depend on it.
5. **Allowlisted recipients are trusted.** Sending HR data to an allowlisted vendor is allowed by the patched rule.
6. **Scripted agent.** It models a vulnerable agent; it is not evidence about any specific real LLM.

## Out of scope
Authentication/RBAC, real integrations, adaptive attackers, model training, DPDP legal certification.
