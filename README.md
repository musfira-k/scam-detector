# Payment Screenshot Scam Detector

An AI-assisted tool that checks payment screenshots and scam messages for warning signs.
Built with FastAPI, Gemini and a dark glassmorphism frontend in plain HTML, CSS and JavaScript.

> **Important:** This tool cannot prove that a payment is genuine. It only looks for red flags.
> Always confirm a payment in your own JazzCash/Easypaisa app or official SMS.

## Features

- Upload a screenshot (JPEG, PNG, WEBP, up to 4 MB) and get a verdict, a risk score (0-100) and a list of red flags
- Three verdicts only: `Suspicious`, `Unclear`, `No red flags found`
- Extracts amount, transaction ID, sender, receiver, date/time and app name
- Safe fallback: any unexpected model output becomes `Unclear`, never `No red flags found`
- Prompt-injection defense: text inside the image is treated as data, never as instructions
- Retries on temporary 503 errors, 45 second timeout, clear error messages
- Images are processed in memory and are not stored
- Cinematic UI: scanning animation, animated risk gauge, mobile friendly

## Architecture

```
Browser (frontend/)  ->  FastAPI backend (main.py)  ->  Gemini API
       resize to 1024px        validate, downscale,        strict JSON
                               retry, validate verdict
```

## Project structure

```
scam-detector/
├── main.py              # FastAPI backend and /analyze endpoint
├── frontend/            # index.html, style.css, app.js
├── requirements.txt
├── .env.example         # copy to .env and add your key
├── test_gemini.py       # times Gemini calls
└── list_models.py       # lists models and tests their speed
```

## Setup

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Open `.env` and set your own values:

```
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-3-flash-preview
ALLOWED_ORIGINS=http://127.0.0.1:3000,http://localhost:3000
```

Model availability changes over time. Run `python list_models.py` to see which models work for your key.

## Run locally

Terminal 1 (backend):
```powershell
uvicorn main:app --reload
```

Terminal 2 (frontend):
```powershell
python -m http.server 3000 --directory frontend
```

Open http://127.0.0.1:3000

## API

`POST /analyze` with a multipart field named `file`.

```json
{
  "verdict": "Suspicious",
  "risk_score": 95,
  "reason": "Short explanation in simple English.",
  "red_flags": ["Impossible date", "Short transaction ID"],
  "extracted_fields": {
    "amount": "Rs. 25,000",
    "transaction_id": "12345",
    "sender": "Sara A.",
    "receiver": "Ali Traders",
    "date_time": null,
    "app_name": "DemoPay"
  },
  "advice": "Please check your JazzCash/Easypaisa app or official SMS to confirm the payment. Do not trust screenshots alone."
}
```

| Status | Meaning |
|---|---|
| 400 | Invalid or empty file |
| 413 | File larger than 4 MB |
| 500 | API key not set |
| 503 | Gemini temporarily unavailable |
| 504 | Gemini took too long |

## Evaluation

_Coming soon: test set of clean and fake receipts, confusion matrix, false positives and average response time._

## Limitations

- A screenshot alone cannot prove a payment is real
- The AI can miss well-made fakes or flag genuine screenshots
- Free Gemini tier data may be used by Google, so do not upload CNIC, OTP, PIN or card numbers
- Preview models can change or be removed without notice

## Privacy

Do not upload images showing CNIC, OTP, PIN or card numbers. Uploaded images are not saved by this app.
