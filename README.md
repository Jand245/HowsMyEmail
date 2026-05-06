# HowIsMyEmail

## About the Project

HowIsMyEmail is a local AI-powered email analysis tool focused on detecting social engineering attacks within email inboxes.

The project was built as part of a cybersecurity focused data-driven security project centered around social engineering detection.

The system is designed to score email inboxes based on social engineering attacks beyond simple phishing by identifying manipulation patterns and tactics within emails.

The application uses:
- A Streamlit-based web interface
- Local LLM inference using HuggingFace Transformers
- Inbox-level and email-level risk scoring
- Structured tagging for social engineering behaviors

---

## Project Structure

```text
HowsMyEmail/clear

│
├── app.py
├── model_runner.py
├── merged/
├── dummy_inboxes/
├── requirements.txt
└── README.md
```

### File Overview

| File | Purpose |
|---|---|
| `app.py` | Streamlit frontend and UI logic |
| `model_runner.py` | Handles model loading and inference |
| `merged/` | Local HuggingFace model files |
| `dummy_inboxes/` | Example inbox datasets |
| `requirements.txt` | Python dependencies |

---

## Input Format

The application expects emails in JSON list format.

Example:

```json
[
  {
    "to": "employee@company.com",
    "from": "security-update@micros0ft-support.com",
    "subject": "Urgent Password Reset Required",
    "header": "SPF failed",
    "encryption": false,
    "body": "Your account will be disabled unless you verify immediately.",
    "signature": "Microsoft Support Team",
    "attachment": false
  }
]
```

---

## Dependencies

Install required packages:

```bash
pip install -r requirements.txt
```

Main dependencies include:
- Python 3.9+
- Streamlit
- Transformers
- Torch
- Accelerate

---

## Model Setup

Place the local HuggingFace model inside the `merged/` directory.

The folder should contain files similar to:

```text
merged/
├── config.json
├── tokenizer.json
├── tokenizer_config.json
├── generation_config.json
├── tokenizer.model
├── model.safetensors
└── chat_template.jinja
```

---

## Running the Application

Run the Streamlit interface with:

```bash
streamlit run app.py
```

The application will open locally in your browser where inboxes can be pasted directly into the interface for analysis.

---

## Notes

- The system is intended for educational and research purposes
- Performance depends heavily on local hardware and model size
- GPU acceleration is recommended for faster inference
- Larger inboxes may increase processing time significantly

---

