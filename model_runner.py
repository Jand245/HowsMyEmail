from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import json
import re

MODEL_PATH = "./merged"

print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)

print("Loading model...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
    device_map="auto"
)

model.eval()
print("Model loaded.\n")


def clean_json_response(response):
    response = response.strip()

    # remove markdown fences
    response = re.sub(r"^```json", "", response)
    response = re.sub(r"^```", "", response)
    response = re.sub(r"```$", "", response)

    response = response.strip()

    # extract JSON block
    match = re.search(r"\{.*\}", response, re.DOTALL)
    if match:
        return match.group(0)

    return response


def analyze_email(email_input):
    email_text = email_input["emails"][0]["body"]

    
    prompt = f"""
    
You are a cybersecurity analyst specializing in social engineering detection.

Your task is to estimate the probability that an email is malicious using structured reasoning.

You must follow this exact process:

Assign a base probability using the risk tier:
tier_1_benign = 0.10
tier_2_dark_pattern = 0.35
tier_3_manipulative = 0.60
tier_4_malicious = 0.85

Risk tier definitions:
tier_1_benign = normal communication with no clear manipulation, deception, or harmful intent.
tier_2_dark_pattern = persuasive, pressured, or nudging behavior without clear evidence of malicious intent.
tier_3_manipulative = deceptive or coercive social engineering with clear manipulation, but without fully explicit malicious outcome.
tier_4_malicious = clear credential theft, account takeover, financial fraud, malware delivery, identity theft, extortion, or scam intent.

Update this probability using observed evidence from the email:

Each signal increases probability within a bounded range. The exact increase should be chosen based on how strong, clear, and direct the signal is in the email.

Layer 4 signals: increase probability by 0.10 to 0.25 each

Use values near 0.10 for weak or implied signals.
Use values near 0.25 for clear, direct, high-confidence signals.

Layer 5 signals: increase probability by 0.05 to 0.15 each

Lower values for ambiguous or partial indicators.
Higher values for strong, clearly observable indicators.

Layer 3 signals: increase probability by 0.02 to 0.08 each

Lower values for subtle or weak persuasion.
Higher values for explicit or aggressive persuasion.

Layer 2 signals: increase probability by 0.01 to 0.05 each

Lower values for general categorization.
Higher values for clearly defined attack patterns.

Important calibration rules:
If the email asks the user to click a link and verify credentials, it must be at least tier_3_manipulative.
If the email combines urgency, account threat, and credential verification, it should usually be tier_4_malicious.
If the email contains a suspicious or lookalike link plus credential/account verification language, it should usually be tier_4_malicious.
Do not label an email tier_4_malicious unless there is clear harmful intent or a clear harmful outcome.
Do not inflate benign marketing or ordinary reminders just because they contain mild urgency.

Apply diminishing returns:
As probability approaches 1.0, reduce the impact of additional signals so the score increases more slowly.

Combine weak signals conservatively:
If multiple weak or moderate signals exist, do not sum them aggressively.
Avoid inflating probability from many low-impact features.

Cap the final probability at 0.99.

Convert the result into a final confidence score using this formula:

final_score = (probability × 100 × 0.7) + (tier_base × 100 × 0.3)

Where:
tier_base is the starting probability from step 1.

Round to the nearest integer and keep the result between 0 and 100.

Email to analyze:
{email_text}

Return only valid JSON.
Do not include markdown.
Do not include explanations outside the JSON.

Return exactly this structure:
{{
  "risk_tier": "tier_1_benign | tier_2_dark_pattern | tier_3_manipulative | tier_4_malicious",
  "confidence": 0,
  "reason": "brief explanation of the strongest evidence"
}}

The risk_tier value must be exactly one of:
tier_1_benign
tier_2_dark_pattern
tier_3_manipulative
tier_4_malicious

The confidence value must be the final_score from the scoring process.


    Email to analyze:
    {email_text}
    """

    messages = [{"role": "user", "content": prompt}]

    # apply chat template
    prompt_text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )

    # tokenize
    inputs = tokenizer(
        prompt_text,
        return_tensors="pt"
    ).to(model.device)

    # generate
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=150,
            do_sample=False
        )

    # decode
    response = tokenizer.decode(
        outputs[0][inputs["input_ids"].shape[-1]:],
        skip_special_tokens=True
    ).strip()

    # clean
    cleaned = clean_json_response(response)

    # parse JSON
    try:
        return json.loads(cleaned)
    except:
        return {
            "risk_tier": "unknown",
            "confidence": 0,
            "reason": response
        }