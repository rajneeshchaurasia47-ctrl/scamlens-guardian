# ScamLens Guardian v4 — Alexa+-style simulated experience

**Hackathon disclosure:** This is a self-contained simulated Alexa+ web experience, NOT an official Alexa+ integration or skill. Rules-based analysis, browser speech recognition, and guided fallback are the default. No paid API required.

## Start on Windows (PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```
Open http://127.0.0.1:8000 in **Google Chrome** for browser speech recognition. Brave may show a `network` error for speech recognition.

## Test
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## What changed in v4
- Hindi localized evidence and urgent incident instructions in guided fallback.
- Bank contact prioritized when a banking OTP is disclosed.
- Avoid repeated analysis-summary chat bubbles.
- URL status explicitly says destination is **not verified**.
- Response engine label moved out of chat transcript.
- Improved browser speech service failure message.

## Security and accuracy
- No website is fetched, scanned, or verified. A low score does not establish safety.
- Do not submit real OTPs, passwords, financial data, or secrets.
- No persistent database; server hosting providers may keep operational logs.
- Optional OpenAI API use requires server-side OPENAI_API_KEY and billing; never expose secrets in JavaScript or commit `.env`.
- Do not claim official Alexa+ connectivity.

## Submission checklist
1. Verify working app locally, including Chrome voice input/output.
2. Publish repository with MIT LICENSE and this README.
3. Deploy on HTTPS host supporting Python/FastAPI.
4. Record an English public YouTube/Vimeo demo under 3 minutes.
5. Submit repository, video, track, project explanation and honest tool/product feedback on Devpost before the deadline.

## Limitations
Rule-based detector, not a verified fraud classification model; no real URL reputation lookup; browser voice recognition depends on platform; not a substitute for banks or emergency responders.

# ScamLens Guardian Pro v3 — Alexa+-style simulated experience

**Track:** Alexa+ simulated experience (web app). **Not** an official Alexa+ integration, skill or Amazon product.

## What is real
- Explainable heuristic scam analysis for messages and URL patterns. No URL is opened/fetched.
- Five interactive fictional scam scenarios and five incident-response action plans.
- Context passed between follow-up turns from browser to server (no database).
- English/Hindi responses, browser speech synthesis and optional browser speech recognition.
- **Optional** OpenAI-powered conversational reasoning when `OPENAI_API_KEY` is configured. Otherwise guided rule-based fallback. Model responses may be incorrect; use only for educational guidance.
- Password/OTP/card-like patterns are redacted before optional model calls; **redaction is not guaranteed** to catch all secrets. Do not paste real sensitive data.

## Run on Windows PowerShell
```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```
Open http://127.0.0.1:8000

## Optional AI conversation
```powershell
$env:OPENAI_API_KEY="YOUR_API_KEY"
$env:OPENAI_MODEL="gpt-4.1-mini"
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```
Requires an API account with access and usage billing. Never put the API key in frontend JavaScript or GitHub. If not configured or API fails, app uses guided fallback.

## Tests
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Deployment
Deploy on a Python-compatible HTTPS host with start command `uvicorn main:app --host 0.0.0.0 --port $PORT` (host-specific port substitution). Add `OPENAI_API_KEY` as server-side secret only if using optional AI. Check that speech recognition is supported by the demo browser; it may use browser-provider services. No database is used; hosts and browser vendors may still log/process data.

## Suggested 2:30 demo
0:00 Problem + disclaimer; 0:20 choose bank scam; 0:40 evidence and link indicators; 1:05 select credentials exposure and show action plan; 1:35 ask voice follow-up; 2:00 compare normal message and uncertainty; 2:20 show GitHub architecture and feedback.

## Limitations / honest disclosure
- A polished prototype, **not** a certified fraud detector, live URL reputation system, bank-integrated agent, or official Alexa+ integration.
- Risk scores are heuristic and not probabilities. False positives and false negatives occur.
- No direct banking, reporting, or autonomous third-party actions.
- Voice input depends on browser compatibility and microphone permissions.
- AI conversation is only active with a configured API key and may incur costs.
- For an Alexa+ simulated-experience entry, clearly explain the simulation path and show the working web app in the demo. Check final event rules before submission.

## Repository
Include this source, MIT LICENSE, and demo screenshots/video. Publish a public repo with no secrets. Add actual tool feedback based on your experience; do not fabricate product testing.
