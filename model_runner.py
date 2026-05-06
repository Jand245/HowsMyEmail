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


TAG_DESCRIPTIONS = {
    "pol_voting_manipulation": "Fake voting deadlines or suppression.",
    "pol_donation_pressure": "Urgent political donation pressure.",
    "pol_disinformation_spread": "Encourages spreading false political information.",
    "fin_account_threat": "Banking account suspension or unusual activity threat.",
    "fin_payment_request": "Payment, invoice, wire, or billing request.",
    "fin_reward_lure": "Refund, prize, cashback, or money bait.",
    "fin_investment_bait": "Unrealistic investment return.",
    "hlt_fear_induction": "Illness, exposure, or medical scare.",
    "hlt_product_scam": "Fake cure, supplement, or treatment.",
    "hlt_data_harvest": "Fake medical portal collecting data.",
    "rel_guilt_obligation": "Moral or spiritual pressure.",
    "rel_donation_manipulation": "Fake religious charity donation.",
    "rel_community_impersonation": "Posing as a religious leader.",
    "mkt_false_scarcity": "Fake limited stock or countdown.",
    "mkt_misleading_claim": "Exaggerated or false offer.",
    "mkt_dark_pattern": "Deceptive marketing or unsubscribe pattern.",
    "mkt_fake_loyalty_bait": "Fake loyalty reward expiration.",
    "edu_scholarship_scam": "Fake scholarship, grant, or award.",
    "edu_fake_certification": "Fake or unaccredited certificate.",
    "edu_awareness_impersonation": "Fake school IT or security notice.",
    "tec_account_takeover_bait": "Fake login, OTP, or account alert.",
    "tec_support_impersonation": "Fake IT, Microsoft, Google, or support help.",
    "tec_software_lure": "Fake software update or install prompt.",
    "tec_cloud_share_lure": "Fake Drive, Dropbox, or document share.",
    "soc_peer_pressure": "Claims others already verified or joined.",
    "soc_charity_fraud": "Fake charity appeal.",
    "soc_fake_survey": "Survey used for data collection.",
    "soc_community_threat": "Local alert used as bait.",
    "emp_fake_job_offer": "Unrealistic job offer.",
    "emp_recruiter_impersonation": "Fake recruiter or HR message.",
    "emp_application_harvest": "Collects applicant data.",
    "emp_payroll_manipulation": "Direct deposit or payroll change.",
    "leg_lawsuit_threat": "Fake lawsuit or legal threat.",
    "leg_copyright_threat": "Fake copyright or DMCA threat.",
    "leg_compliance_bait": "Fake compliance or policy update.",
    "leg_authority_impersonation": "Fake government or legal authority.",
    "nws_fake_breaking_news": "Fabricated urgent news.",
    "nws_clickbait_headline": "Outrage or curiosity headline.",
    "nws_confirmation_bias": "Reinforces beliefs deceptively.",
    "nws_share_amplification": "Urges forwarding or sharing.",
    "per_romance_manipulation": "Fake relationship manipulation.",
    "per_grief_crisis_exploit": "Grief or crisis exploitation.",
    "per_shame_extortion": "Shame, blackmail, or sextortion.",
    "per_savior_bait": "Urgent appeal to save or help someone.",
    "urgency_pressure": "Deadline or immediate action pressure.",
    "fear_threat": "Threat, consequence, danger, or punishment.",
    "guilt_shame": "Obligation, blame, or shame pressure.",
    "greed_reward": "Prize, gain, refund, or reward.",
    "social_proof": "Claims others already did it.",
    "reciprocity": "Suggests the user owes something back.",
    "curiosity_bait": "Pushes the user to click to see hidden information.",
    "false_scarcity": "Limited availability or countdown pressure.",
    "personalization": "Uses personal details to increase credibility.",
    "emotional_exploitation": "Leverages emotions to influence action.",
    "credential_harvest": "Attempts to steal login, password, MFA, or OTP information.",
    "financial_fraud": "Payment, wire, invoice, or gift card scam.",
    "malware_delivery": "Attempts to deliver malicious attachment or download.",
    "data_exfiltration": "Attempts to collect sensitive data.",
    "account_takeover": "Attempts account access or session compromise.",
    "identity_theft": "Collects identity information.",
    "disinformation": "Spreads false information.",
    "behavioral_manipulation": "Deceptively influences user action.",
    "extortion_blackmail": "Uses threats for compliance or payment.",
    "spoofed_sender": "Sender mismatch or impersonation.",
    "lookalike_domain": "Fake domain mimicking a real one.",
    "auth_fail": "SPF, DKIM, or DMARC failure.",
    "suspicious_url": "Risky, mismatched, or action link.",
    "risky_attachment": "Executable, macro, or suspicious file.",
    "thread_hijack": "Inserted into an existing thread."
}


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
    objects = []

    pattern = r'\{\s*"risk_tier"\s*:\s*.*?"tags"\s*:\s*\{.*?\}\s*\}'
    matches = re.findall(pattern, response, re.DOTALL)

    for match in matches:
        try:
            objects.append(json.loads(match))
        except json.JSONDecodeError:
            pass

    return objects


def normalize_tag_item(item):
    if isinstance(item, dict):
        tag_name = item.get("tag", "")

        return {
            "tag": tag_name,
            "description": item.get("description") or TAG_DESCRIPTIONS.get(tag_name, ""),
            "reason": item.get("reason", "")
        }

    tag_name = str(item)

    return {
        "tag": tag_name,
        "description": TAG_DESCRIPTIONS.get(tag_name, ""),
        "reason": ""
    }


def normalize_result_objects(result):
    cleaned = []

    for label in result:
        risk_tier = label.get("risk_tier", "tier_1_benign")
        domain_tag = label.get("domain_tag", "technology")
        risk_summary = label.get("risk_summary", "No summary returned.")

        tags = label.get("tags", {})

        cleaned.append({
            "risk_tier": risk_tier,
            "domain_tag": domain_tag,
            "risk_summary": risk_summary,
            "tags": {
                "layer_2": [
                    normalize_tag_item(item)
                    for item in tags.get("layer_2", [])
                ],
                "layer_3": [
                    normalize_tag_item(item)
                    for item in tags.get("layer_3", [])
                ],
                "layer_4": [
                    normalize_tag_item(item)
                    for item in tags.get("layer_4", [])
                ],
                "layer_5": [
                    normalize_tag_item(item)
                    for item in tags.get("layer_5", [])
                ],
            }
        })

    return cleaned


def analyze_email(email_input):
    email_text = json.dumps(email_input["emails"], indent=2)

    prompt = f"""
You are labeling emails for a cybersecurity social engineering demo portal.

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
5. For each selected tag, include:
   - tag
   - description
   - reason
6. Write a short risk_summary for the email in normal user-friendly language.
7. Leave a layer array empty only when no valid tag from that layer fits the email.

Return one label object per input email.
Return labels in the same order as the input emails.

OUTPUT FORMAT

Return only valid JSON.
Return a JSON array.
Do not include markdown.
Do not include explanations outside the JSON.
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
    "risk_summary": "This email appears to be a normal account notification with no strong social engineering pressure.",
    "tags": {{
      "layer_2": [
        {{
          "tag": "tec_account_takeover_bait",
          "description": "Fake login, OTP, or account alert.",
          "reason": "The message asks the user to respond to an account access issue."
        }}
      ],
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
            max_new_tokens=1400,
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

    return normalize_result_objects(result)