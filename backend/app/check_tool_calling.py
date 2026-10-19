"""Does your Nebius account support tool calling for the agent model?  Run: python -m app.check_tool_calling"""
from app.config import get_settings, load_dotenv
from app.services import nemotron_client
from app.services.llm_agent import TOOLS
from app.services.nemotron_client import NemotronError


def main() -> None:
    load_dotenv()
    s = get_settings()
    if not s.api_key:
        print("NEBIUS_API_KEY is not set (see ../.env).")
        return
    models = [m for m in dict.fromkeys([s.agent_model, s.super_model]) if m]
    if not models:
        print("Set AGENT_MODEL or NEMOTRON_NANO_MODEL in ../.env first.")
        return
    messages = [{"role": "system", "content": "You are an office assistant. Use the tools to complete tasks."},
                {"role": "user", "content": "Read the email with id vendor_email_001 and tell me what it says."}]
    for model in models:
        print(f"\n== {model} ==")
        try:
            out = nemotron_client.chat_raw(model, messages, TOOLS, 0.0, s)
        except NemotronError as exc:
            print("FAILED:", exc)
            print("If this says HTTP 400/404 about tools, this model may not support tool calling on your endpoint.")
            continue
        msg = out["message"]
        calls = msg.get("tool_calls") or []
        print(f"finish_reason={out['finish_reason']}  latency={out['latency_ms']} ms  "
              f"tokens={out['prompt_tokens']}/{out['completion_tokens']}")
        if calls:
            for c in calls:
                print("TOOL CALL:", c["function"]["name"], c["function"].get("arguments"))
            print("OK: tool calling works.")
        else:
            print("No tool call returned. Reply was:", (msg.get("content") or "")[:200])
            print("The model answered in text instead of calling a tool. Try the other model or tell me this output.")


if __name__ == "__main__":
    main()
