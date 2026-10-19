"""Check your Nebius Token Factory setup.  Run from backend/:  python -m app.check_nebius

Lists model IDs that mention 'nemotron' and sends one tiny test message to your configured Super model.
Never prints your API key.
"""
import sys

import httpx

from app.config import get_settings, load_dotenv


def main() -> None:
    load_dotenv()
    s = get_settings()
    if not s.api_key:
        print("NEBIUS_API_KEY is not set. Create ../.env from .env.example and fill it in.")
        return
    base = s.base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {s.api_key}"}
    try:
        r = httpx.get(f"{base}/models", headers=headers, timeout=30)
    except httpx.HTTPError as exc:
        print(f"Could not reach {base}: {type(exc).__name__}")
        return
    if r.status_code != 200:
        print(f"Model list failed: HTTP {r.status_code}. Check the key and base URL.")
        return
    ids = sorted(m["id"] for m in r.json().get("data", []))
    nemotron = [i for i in ids if "nemotron" in i.lower()]
    print(f"{len(ids)} models available.")
    if "--all" in sys.argv:
        print("All model IDs:")
        for i in ids:
            print("  ", i)
        return
    print("Nemotron models:" if nemotron else "No model IDs mention 'nemotron'. First 30 models:")
    for i in (nemotron or ids[:30]):
        print("  ", i)
    if not s.super_model:
        print("\nNEMOTRON_SUPER_MODEL is not set: copy one of the IDs above into ../.env.")
        return
    print(f"\nTest call to {s.super_model} ...")
    r = httpx.post(f"{base}/chat/completions", headers=headers, timeout=120, json={
        "model": s.super_model, "max_tokens": min(s.max_tokens, 2000),
        "messages": [{"role": "user", "content": "Reply with the single word OK."}]})
    print("HTTP", r.status_code)
    if r.status_code != 200:
        print(r.text[:300])
        return
    choice = r.json()["choices"][0]
    content = choice["message"].get("content")
    print("Finish reason:", choice.get("finish_reason"))
    print("Reply:", content)
    if not content:
        print("Empty reply. This is usually a reasoning model that used all its tokens thinking.")
        print("Try a larger NEMOTRON_MAX_TOKENS in ../.env (for example 4000) and run this again.")


if __name__ == "__main__":
    main()
