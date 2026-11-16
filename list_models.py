import os
import time
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    raise SystemExit("GEMINI_API_KEY is not set in .env")

client = genai.Client(
    api_key=api_key,
    http_options=types.HttpOptions(timeout=15000),  # 15 seconds
)

names = []
for m in client.models.list():
    actions = getattr(m, "supported_actions", None) or []
    if "generateContent" in actions:
        names.append(m.name)

print(f"{len(names)} models support generateContent:")
for n in names:
    print("  ", n)

skip = ("image", "tts", "embedding", "live", "audio")
candidates = [n for n in names if "flash" in n and not any(s in n for s in skip)][:8]

print("\nSpeed test ('Say OK'):")
results = []
for n in candidates:
    start = time.time()
    try:
        client.models.generate_content(model=n, contents="Say OK")
        results.append((time.time() - start, n, "OK"))
    except Exception as e:
        results.append((time.time() - start, n, str(e)[:80]))

results.sort()
for secs, n, status in results:
    print(f"{secs:6.1f}s  {n}  {status}")