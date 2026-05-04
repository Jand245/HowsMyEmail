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
    
)


model.to("cuda" if torch.cuda.is_available() else "cpu")

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
    # send full inbox instead of one email
    email_text = json.dumps(email_input["emails"], indent=2)

    prompt = f"""
    You are a cybersecurity analyst specializing in social engineering detection.

You will receive a list of emails.

You must treat each email as an independent case.
Do not merge emails.
Do not average behavior mentally.

Your task is to estimate the probability that each email is malicious using structured reasoning, then compute a final inbox-level score.

BATCH PROCESSING REQUIREMENT


First, count how many email objects are in the input list. Call this number N.

Process the batch as N separate emails.

For each email object in the list:
- score that email
- assign that email one domain_tag
- assign that email layer tags
- add one score to email_scores
- add one object to email_results

The inbox_score is calculated only after all N email scores exist.

--------------------------------
PER-EMAIL SCORING PROCESS
--------------------------------

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

Layer 4 signals: increase probability by 0.10 to 0.25 each  
Layer 5 signals: increase probability by 0.05 to 0.15 each  
Layer 3 signals: increase probability by 0.02 to 0.08 each  
Layer 2 signals: increase probability by 0.01 to 0.05 each  

Use higher values for strong, explicit signals and lower values for weak or implied ones.

Important calibration rules:
- If an email asks the user to click a link and verify credentials, it must be at least tier_3_manipulative.
- If urgency + account threat + credential verification are present, it should usually be tier_4_malicious.
- Do not assign tier_4 without clear harmful intent.
- Do not inflate benign emails due to mild urgency alone.

Apply diminishing returns:
As probability approaches 1.0, reduce the impact of additional signals.

Combine weak signals conservatively:
Do not over-sum many small indicators.

Cap probability at 0.99.

Convert to a score:

final_score = (probability × 100 × 0.7) + (tier_base × 100 × 0.3)

--------------------------------
TAGGING OUTPUT ADDITION
--------------------------------

For each email, also return the domain and layer tags used for that email.

Each email must have exactly one domain_tag.

Domain tag options:
political, financial, technology, health, education, employment, legal, news_media, marketing, personal_emotional, religious, social_community

Layer fields must always be arrays.
Use empty arrays if no tags apply.

Layer 2 examples:
tec_account_takeover_bait, tec_support_impersonation, tec_software_lure, tec_cloud_share_lure,
fin_account_threat, fin_payment_request, fin_reward_lure,
emp_payroll_manipulation, emp_recruiter_impersonation,
edu_credential_phishing,
leg_authority_impersonation, leg_lawsuit_threat, leg_copyright_threat,
per_romance_manipulation, per_shame_extortion,
soc_charity_fraud

Layer 3 examples:
urgency_pressure, fear_threat, authority_appeal, curiosity_bait, emotional_exploitation, greed_reward, personalization, commitment_escalation

Layer 4 examples:
credential_harvest, account_takeover, financial_fraud, data_exfiltration, identity_theft, malware_delivery, behavioral_manipulation

Layer 5 examples:
spoofed_sender, lookalike_domain, suspicious_url, risky_attachment, auth_fail, thread_hijack

--------------------------------
INBOX AGGREGATION
--------------------------------

After scoring all emails individually:

- Compute the average of all email scores
- Identify the maximum (highest) email score

Then compute the final inbox score:

inbox_score = (average × 0.6) + (max × 0.4)

Rationale:
- The average represents overall inbox risk
- The maximum preserves the impact of the most dangerous email
- The weighting ensures high-risk emails do not disappear into the average

--------------------------------
INPUT
--------------------------------

Emails:
{email_text}

--------------------------------
OUTPUT
--------------------------------

Return valid JSON only.
Do not use markdown.

Return exactly this structure:

{{
  "risk_tier" : "inbox_level",
  "inbox_score": 0,
  "email_scores": [0],
  "email_results": [
    {{
      "score": 0,
      "domain_tag": "technology",
      "layer_2": [],
      "layer_3": [],
      "layer_4": [],
      "layer_5": []
    }}
  ],
  "reason": "brief explanation of overall inbox risk and any high-risk emails"
}}

Important:
- email_scores must contain one score per input email.
- email_results must contain one object per input email.
- email_results must be in the same order as the input emails.
- score inside email_results must match the matching value in email_scores.
- layer_2, layer_3, layer_4, and layer_5 must always be arrays.
- domain_tag must always be exactly one string.

"""

    messages = [{"role": "user", "content": prompt}]

    prompt_text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )

    inputs = tokenizer(
        prompt_text,
        return_tensors="pt"
    ).to(model.device)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=900,
            do_sample=False
        )

    response = tokenizer.decode(
        outputs[0][inputs["input_ids"].shape[-1]:],
        skip_special_tokens=True
    ).strip()

    cleaned = clean_json_response(response)

    try:
        result = json.loads(cleaned)
    except json.JSONDecodeError:
        raise ValueError(f"Model did not return valid JSON:\n{response}")

    # Convert 0–1 → 0–100
    if "inbox_score" in result and result["inbox_score"] <= 1:
        result["inbox_score"] = round(result["inbox_score"] * 100)

    if "email_scores" in result:
        result["email_scores"] = [
            round(score * 100) if score <= 1 else round(score)
            for score in result["email_scores"]
        ]

    if "email_results" in result:
        for email in result["email_results"]:
            if "score" in email and email["score"] <= 1:
                email["score"] = round(email["score"] * 100)

    # normalize risk tier
    if result.get("risk_tier") == "4":
        result["risk_tier"] = "tier_4_malicious"

    return result