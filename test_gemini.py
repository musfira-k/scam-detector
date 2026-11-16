import os
import sys
import time
import asyncio
from dotenv import load_dotenv
from google import genai
from google.genai import types

TIMEOUT_SECONDS = 60.0
IMAGE_FILENAME = "sample_suspicious.png"


async def run_call_with_timeout(func, *args, **kwargs):
    """Run a blocking function in a separate thread with a 60-second timeout."""
    return await asyncio.wait_for(
        asyncio.to_thread(func, *args, **kwargs),
        timeout=TIMEOUT_SECONDS,
    )


async def main():
    load_dotenv()

    api_key = os.getenv("GEMINI_API_KEY")
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    print("========================================")
    print("   Gemini API Performance & Test Suite  ")
    print("========================================")
    print(f"Model: {model_name}")
    print(f"API Key configured: {'YES' if api_key else 'NO'}")
    print(f"Call Timeout: {TIMEOUT_SECONDS}s")
    print("========================================\n")

    if not api_key:
        print("[ERROR] GEMINI_API_KEY is not set in your .env file.")
        sys.exit(1)

    try:
        client = genai.Client(api_key=api_key)
    except Exception as exc:
        print(f"[ERROR] Failed to initialize Gemini client: {exc}")
        sys.exit(1)

    # ----------------------------------------------------
    # TEST A: Text-only prompt "Say OK"
    # ----------------------------------------------------
    print("[TEST A] Text-only prompt: 'Say OK'")
    start_a = time.perf_counter()
    try:
        response_a = await run_call_with_timeout(
            client.models.generate_content,
            model=model_name,
            contents=["Say OK"],
        )
        elapsed_a = time.perf_counter() - start_a
        text_a = (response_a.text or "").strip()
        print(f"  -> Result: Success ({elapsed_a:.2f} seconds)")
        print(f"  -> Response: \"{text_a}\"\n")
    except asyncio.TimeoutError:
        elapsed_a = time.perf_counter() - start_a
        print(f"  -> [TIMEOUT] Test A exceeded {TIMEOUT_SECONDS} seconds ({elapsed_a:.2f}s)\n")
    except Exception as exc:
        elapsed_a = time.perf_counter() - start_a
        print(f"  -> [EXCEPTION] Test A failed after {elapsed_a:.2f}s: {type(exc).__name__}: {exc}\n")

    # ----------------------------------------------------
    # Check for sample_suspicious.png for Tests B & C
    # ----------------------------------------------------
    image_path = os.path.abspath(IMAGE_FILENAME)
    if not os.path.exists(image_path):
        print(f"[NOTICE] '{IMAGE_FILENAME}' not found in {os.getcwd()}.")
        print("         Tests B and C require this file. Please provide it to run Tests B & C.\n")
        return

    try:
        with open(image_path, "rb") as f:
            image_bytes = f.read()
        print(f"[INFO] Loaded '{IMAGE_FILENAME}' ({len(image_bytes)} bytes).\n")
    except Exception as exc:
        print(f"[ERROR] Failed to read '{IMAGE_FILENAME}': {exc}\n")
        return

    image_part = types.Part.from_bytes(
        data=image_bytes,
        mime_type="image/png",
    )
    prompt_text = "Describe this image in one sentence"

    # ----------------------------------------------------
    # TEST B: Image prompt, NO thinking_config
    # ----------------------------------------------------
    print(f"[TEST B] Image prompt: '{prompt_text}' (no thinking_config)")
    start_b = time.perf_counter()
    try:
        response_b = await run_call_with_timeout(
            client.models.generate_content,
            model=model_name,
            contents=[image_part, prompt_text],
        )
        elapsed_b = time.perf_counter() - start_b
        text_b = (response_b.text or "").strip()
        print(f"  -> Result: Success ({elapsed_b:.2f} seconds)")
        print(f"  -> Response: \"{text_b}\"\n")
    except asyncio.TimeoutError:
        elapsed_b = time.perf_counter() - start_b
        print(f"  -> [TIMEOUT] Test B exceeded {TIMEOUT_SECONDS} seconds ({elapsed_b:.2f}s)\n")
    except Exception as exc:
        elapsed_b = time.perf_counter() - start_b
        print(f"  -> [EXCEPTION] Test B failed after {elapsed_b:.2f}s: {type(exc).__name__}: {exc}\n")

    # ----------------------------------------------------
    # TEST C: Image prompt WITH thinking_config=ThinkingConfig(thinking_budget=0)
    # ----------------------------------------------------
    print(f"[TEST C] Image prompt: '{prompt_text}' WITH thinking_config=ThinkingConfig(thinking_budget=0)")
    start_c = time.perf_counter()
    try:
        config_c = types.GenerateContentConfig(
            thinking_config=types.ThinkingConfig(thinking_budget=0)
        )
        response_c = await run_call_with_timeout(
            client.models.generate_content,
            model=model_name,
            contents=[image_part, prompt_text],
            config=config_c,
        )
        elapsed_c = time.perf_counter() - start_c
        text_c = (response_c.text or "").strip()
        print(f"  -> Result: Success ({elapsed_c:.2f} seconds)")
        print(f"  -> Response: \"{text_c}\"\n")
    except asyncio.TimeoutError:
        elapsed_c = time.perf_counter() - start_c
        print(f"  -> [TIMEOUT] Test C exceeded {TIMEOUT_SECONDS} seconds ({elapsed_c:.2f}s)\n")
    except Exception as exc:
        elapsed_c = time.perf_counter() - start_c
        print(f"  -> [EXCEPTION] Test C failed after {elapsed_c:.2f}s: {type(exc).__name__}: {exc}\n")

    print("========================================")
    print("             Tests Completed            ")
    print("========================================")


if __name__ == "__main__":
    asyncio.run(main())

