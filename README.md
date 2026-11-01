# SunoSafe – Voice Safety Companion

SunoSafe is a voice-based safety assistant designed to help people, particularly elderly users, understand suspicious phone conversations and identify potential fraud warning signs.

The application analyses an uploaded call recording, generates a transcript, looks for suspicious behaviour and provides practical safety recommendations. Users can also listen to the safety report in Hindi or Telugu.

## The problem

Phone scams often rely on urgency, impersonation, threats and requests for sensitive information. People may not always recognise these warning signs, especially when conversations involve multiple languages or unfamiliar financial terminology.

SunoSafe aims to make these conversations easier to understand through transcription, contextual analysis and spoken guidance.

## How it works

1. **Audio upload:** The user uploads a call recording they own or have permission to analyse.
2. **Speech recognition:** Gnani Prisma converts the recording into text and supports multilingual and code-mixed conversations.
3. **Initial analysis:** A rule-based engine checks for known warning patterns, including credential requests, suspicious payments, impersonation and remote-access instructions.
4. **Contextual analysis:** When enabled, Google Gemini examines the transcript to understand intent, negation, conversation sequence and actions already taken by the recipient.
5. **Risk assessment:** The application combines detected signals and supporting evidence to produce a heuristic risk score.
6. **Safety report:** The user receives an explanation of the findings and recommended next steps.
7. **Spoken guidance:** Gnani Timbre generates an audio explanation in Hindi or Telugu.

## Technology

| Component | Technology |
|---|---|
| Backend | Python, FastAPI |
| Speech-to-text | Gnani Prisma |
| Contextual analysis | Google Gemini |
| Text-to-speech | Gnani Timbre |
| Frontend | HTML, CSS, JavaScript |
| Testing | Pytest |
| Evaluation | Labelled synthetic conversation scenarios |

## Project structure

```text
SunoSafe/
├── main.py
├── requirements.txt
├── run_windows.ps1
├── static/
│   └── index.html
├── tests/
│   ├── test_analysis.py
│   └── test_app.py
├── evaluation/
│   ├── evaluate_rules.py
│   ├── evaluate_pipeline.py
│   ├── scenarios.json
│   └── scenarios_v2.json
├── examples/
│   └── call_scripts.md
├── docs/
├── .env.example
├── .gitignore
└── README.md
```

## Running locally

### Requirements

- Python 3.11
- Gnani API credentials
- Google Gemini API key for optional contextual analysis

### Setup

Clone the repository and enter the project directory.

Create a virtual environment:

```bash
python -m venv .venv
```

Install dependencies:

```bash
.venv\Scripts\activate
pip install -r requirements.txt
```

Configure the required credentials in a local `.env` file. Refer to `.env.example` for the required variable names.

Start the application on Windows:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_windows.ps1
```

Open:

```text
http://127.0.0.1:8000
```

## Testing

Run the automated tests:

```bash
python -m pytest -q
```

Run the phrase-rule evaluation:

```bash
python evaluation/evaluate_rules.py
```

Run the complete offline evaluation:

```bash
python evaluation/evaluate_pipeline.py --limit 0
```

The optional live Gemini evaluation can be run with:

```bash
python evaluation/evaluate_pipeline.py --live-gemini --limit 8 --timeout 20
```

Live evaluation consumes API quota and requires valid credentials.

## Important design considerations

- A keyword by itself is not enough to establish that a call is fraudulent.
- The analysis considers the surrounding conversation and supporting evidence.
- A recipient describing a past incident should not automatically be treated as someone making a suspicious request.
- The displayed risk score is heuristic. It is not a probability of fraud or a guarantee that a call is safe.
- Contextual AI is optional and may be unavailable because of network or model-service failures.
- Transcription errors and code-mixed speech can affect the final assessment.
- The application currently analyses uploaded recordings; it does not automatically monitor or intercept incoming calls.

## Data and privacy

Recordings are sent to Gnani for speech recognition. When contextual analysis is enabled, the resulting transcript is also sent to Google Gemini.

Only analyse recordings for which you have appropriate permission. Do not commit recordings, transcripts containing personal information, API credentials or other sensitive data to the repository.

## Current limitations

SunoSafe is a prototype. Its detection performance needs further evaluation on diverse, representative real-world conversations. Synthetic test scenarios are useful for regression testing, but they do not establish real-world accuracy.

The application should be treated as a decision-support tool, not a replacement for independent verification or official fraud-reporting channels.

## Project status

The current version includes audio analysis, multilingual transcription, rule-based detection, optional contextual reasoning, evidence-based reporting and spoken safety recommendations.

Further work is focused on reducing false positives, identifying missed scam patterns and improving performance across languages.

---

**Development note:** Document the implementation decisions, testing performed and any AI-assisted development in accordance with the internship challenge's disclosure requirements.
