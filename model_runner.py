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
    torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
)

model.to("cuda" if torch.cuda.is_available() else "cpu")
model.eval()
print("Model loaded.\n")


def clean_json_response(response):
    response = response.strip()

    response = re.sub(r"^```json", "", response)
    response = re.sub(r"^```", "", response)
    response = re.sub(r"```$", "", response)

    response = response.strip()

    array_match = re.search(r"\[.*\]", response, re.DOTALL)
    if array_match:
        return array_match.group(0)

    object_match = re.search(r"\{.*\}", response, re.DOTALL)
    if object_match:
        return object_match.group(0)

    return response


def extract_label_objects(response):
    """
    Backup parser for when the model starts valid JSON
    but over-generates or gets cut off.
    """

    objects = []

    pattern = r'\{\s*"risk_tier"\s*:\s*.*?"tags"\s*:\s*\{\s*"layer_2"\s*:\s*\[.*?\]\s*,\s*"layer_3"\s*:\s*\[.*?\]\s*,\s*"layer_4"\s*:\s*\[.*?\]\s*,\s*"layer_5"\s*:\s*\[.*?\]\s*\}\s*\}'

    matches = re.findall(pattern, response, re.DOTALL)

    for match in matches:
        try:
            objects.append(json.loads(match))
        except json.JSONDecodeError:
            pass

    return objects


def analyze_email(email_input):
    email_text = json.dumps(email_input["emails"], indent=2)

    prompt = f"""
You are labeling emails for a cybersecurity social engineering dataset.

You will receive a small batch of email objects.

Each email object uses this format:

{{
  "to": "",
  "from": "",
  "subject": "",
  "header": "",
  "encryption": false,
  "body": "",
  "signature": "",
  "attachment": false
}}

Your job is to evaluate each email object independently and assign labels using only the schema below.

For each email:
1. Read the subject, header, body, sender, signature, attachment value, and encryption value.
2. Choose exactly one risk_tier.
3. Choose exactly one domain_tag.
4. Choose any supported layer tags from layer_2, layer_3, layer_4, and layer_5.
5. Leave a layer array empty only when no valid tag from that layer fits the email.

Return one label object per input email.
Return labels in the same order as the input emails.

OUTPUT FORMAT

Return only valid JSON.
Return a JSON array.
Do not include markdown.
Do not include explanations.
Do not include email_1, email_2, or any invented domain names.

The output array length must equal the number of input email objects.
If there are 5 input emails, return exactly 5 output objects.
Do not split one email into multiple labels.
Do not create extra labels.
Stop immediately after the final closing ].

Each output object must follow this exact shape:

[
  {{
    "risk_tier": "tier_1_benign",
    "domain_tag": "technology",
    "tags": {{
      "layer_2": [],
      "layer_3": [],
      "layer_4": [],
      "layer_5": []
    }}
  }}
]

VALID domain_tag VALUES
political
financial
health
religious
marketing
education
technology
social_community
employment
legal
news_media
personal_emotional

VALID risk_tier VALUES
tier_1_benign
tier_2_dark_pattern
tier_3_manipulative
tier_4_malicious

VALID layer_2 TAGS
pol_voting_manipulation: fake voting deadlines or suppression
pol_donation_pressure: urgent political donation pressure
pol_disinformation_spread: encourages spreading false political information
fin_account_threat: banking account suspension or unusual activity
fin_payment_request: payment invoice wire or billing request
fin_reward_lure: refund prize cashback or money bait
fin_investment_bait: unrealistic investment return
hlt_fear_induction: illness exposure medical scare
hlt_product_scam: fake cure supplement or treatment
hlt_data_harvest: fake medical portal collecting data
rel_guilt_obligation: moral or spiritual pressure
rel_donation_manipulation: fake religious charity donation
rel_community_impersonation: posing as religious leader
mkt_false_scarcity: fake limited stock or countdown
mkt_misleading_claim: exaggerated or false offer
mkt_dark_pattern: deceptive marketing or unsubscribe pattern
mkt_fake_loyalty_bait: fake loyalty reward expiration
edu_scholarship_scam: fake scholarship grant or award
edu_fake_certification: fake or unaccredited certificate
edu_awareness_impersonation: fake school IT or security notice
tec_account_takeover_bait: fake login OTP or account alert
tec_support_impersonation: fake IT Microsoft Google or support help
tec_software_lure: fake software update or install prompt
tec_cloud_share_lure: fake Drive Dropbox or document share
soc_peer_pressure: others already verified or joined
soc_charity_fraud: fake charity appeal
soc_fake_survey: survey used for data collection
soc_community_threat: local alert used as bait
emp_fake_job_offer: unrealistic job offer
emp_recruiter_impersonation: fake recruiter or HR
emp_application_harvest: collects applicant data
emp_payroll_manipulation: direct deposit or payroll change
leg_lawsuit_threat: fake lawsuit or legal threat
leg_copyright_threat: fake copyright or DMCA threat
leg_compliance_bait: fake compliance policy update
leg_authority_impersonation: fake government or legal authority
nws_fake_breaking_news: fabricated urgent news
nws_clickbait_headline: outrage or curiosity headline
nws_confirmation_bias: reinforces beliefs deceptively
nws_share_amplification: urges forwarding or sharing
per_romance_manipulation: fake relationship manipulation
per_grief_crisis_exploit: grief or crisis exploitation
per_shame_extortion: shame blackmail or sextortion
per_savior_bait: urgent appeal to save or help someone

VALID layer_3 TAGS
urgency_pressure: deadline or immediate action pressure
fear_threat: threat consequence danger punishment
guilt_shame: obligation blame shame pressure
greed_reward: prize gain refund reward
social_proof: others already did it
reciprocity: we helped now you owe
curiosity_bait: click to see hidden information
false_scarcity: limited availability or countdown
personalization: uses personal details
emotional_exploitation: leverages emotions

VALID layer_4 TAGS
credential_harvest: login password MFA OTP theft
financial_fraud: payment wire invoice gift card scam
malware_delivery: malicious attachment or download
data_exfiltration: collects sensitive data
account_takeover: account access or session compromise
identity_theft: collects identity information
disinformation: spreads false information
behavioral_manipulation: deceptive influence of user action
extortion_blackmail: threats for compliance or payment

VALID layer_5 TAGS
spoofed_sender: sender mismatch or impersonation
lookalike_domain: fake domain mimicking real one
auth_fail: SPF DKIM DMARC failure
suspicious_url: risky mismatched or action link
risky_attachment: executable macro or suspicious file
thread_hijack: inserted into existing thread

INPUT EMAILS

{email_text}
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
            do_sample=False,
            eos_token_id=tokenizer.eos_token_id,
            pad_token_id=tokenizer.eos_token_id
        )

    response = tokenizer.decode(
        outputs[0][inputs["input_ids"].shape[-1]:],
        skip_special_tokens=True
    ).strip()

    cleaned = clean_json_response(response)

    try:
        result = json.loads(cleaned)
    except json.JSONDecodeError:
        result = extract_label_objects(response)

        if not result:
            raise ValueError(f"Model did not return valid JSON:\n{response}")

    if isinstance(result, dict):
        result = [result]

    expected_count = len(email_input["emails"])
    result = result[:expected_count]

    return result