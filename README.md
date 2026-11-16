# Payment Screenshot Scam Detector

A simple FastAPI service that checks payment screenshots (like JazzCash and Easypaisa) for scam and forgery signs using the Gemini API.

---

## Features

- **Fast & Simple**: Upload a screenshot to check if it looks edited or suspicious.
- **Strict Verdicts**: Every result is classified into one of three simple labels:
  - `Suspicious`: Signs of editing, fake templates, or manipulation found.
  - `Unclear`: Blurry image, cropped image, or not a payment screenshot.
  - `No red flags found`: No obvious signs of editing detected.
  *(Note: The word "Real" is never used for a verdict).*
- **Safety Advice**: Every response includes practical safety advice:
  > *"Please check your JazzCash/Easypaisa app or official SMS to confirm the payment. Do not trust screenshots alone."*
- **File Limit**: Images up to 4 MB are supported.
- **Automatic Retry**: If the Gemini API returns a temporary 503 error, the system automatically retries up to 3 times.
- **Built-in Web Page**: Open your browser to test images directly.

---

## Project Structure

```text
scam-detector/
├── main.py              # FastAPI application and endpoints
├── requirements.txt     # Python dependencies
├── .env.example         # Example environment variables
├── .gitignore           # Git ignore rules (.env, venv/, etc.)
└── README.md            # Simple project documentation
```

---

## Getting Started

### 1. Set Up a Virtual Environment

```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Add Your Gemini API Key

Copy `.env.example` to `.env`:

```bash
# Windows
Copy-Item .env.example .env

# macOS / Linux
cp .env.example .env
```

Open `.env` and put your Google Gemini API key:

```env
GEMINI_API_KEY=your_actual_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```

---

## Running the Server

Start the FastAPI app with Uvicorn:

```bash
uvicorn main:app --reload
```

The server starts at: `http://127.0.0.1:8000`

---

## How to Use

### 1. Simple Web Page

Open `http://127.0.0.1:8000` in your web browser:
1. Click to choose a payment screenshot (under 4 MB).
2. Click **Check Screenshot**.
3. View the verdict, explanation, and safety advice.

### 2. API Endpoint (`POST /analyze`)

Send a `POST` request with a multipart form upload:

```bash
curl -X POST "http://127.0.0.1:8000/analyze" \
  -H "accept: application/json" \
  -F "image=@screenshot.png;type=image/png"
```

#### Example API Response:

```json
{
  "verdict": "Suspicious",
  "reason": "The transaction ID font is misaligned and the font weight differs from standard app text.",
  "advice": "Please check your JazzCash/Easypaisa app or official SMS to confirm the payment. Do not trust screenshots alone.",
  "filename": "screenshot.png",
  "content_type": "image/png",
  "size_bytes": 184320,
  "model": "gemini-2.5-flash"
}
```

### 3. Health Check (`GET /health`)

Check server and API key status:

```bash
curl "http://127.0.0.1:8000/health"
```

---

## Error Messages (in Simple English)

- `400 Bad Request`: "Invalid file type. Please upload an image file (e.g. JPEG, PNG, WEBP)." or "The uploaded file is empty."
- `413 Request Entity Too Large`: "File size exceeds the 4 MB limit."
- `500 Internal Server Error`: "GEMINI_API_KEY is not set. Please add it to your .env file."
- `503 Service Unavailable`: "Gemini service is temporarily unavailable after 3 retry attempts. Please try again later."

