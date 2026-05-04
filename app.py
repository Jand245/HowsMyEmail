import streamlit as st
import json
import re
from collections import Counter
from model_runner import analyze_email

BATCH_SIZE = 5

st.set_page_config(page_title="HowsMyEmail", layout="wide")

st.title("HowsMyEmail")
st.caption("Demo interface for analyzing email social engineering risk")

st.header("1. Input")
st.write("Paste a JSON list of emails, or paste multiple plain-text emails separated by `---` or starting with `Subject:`.")

email_text = st.text_area("Paste inbox content here", height=300)

st.header("2. Analysis")
st.write("The local model connects through `model_runner.py`.")

run_analysis = st.button("Run Analysis")

st.header("3. Results")


def chunk_list(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def score_label(label):

    tier_aliases = {
        1: "tier_1_benign",
        2: "tier_2_dark_pattern",
        3: "tier_3_manipulative",
        4: "tier_4_malicious",
        "1": "tier_1_benign",
        "2": "tier_2_dark_pattern",
        "3": "tier_3_manipulative",
        "4": "tier_4_malicious",
    }

    tier_base_map = {
        "tier_1_benign": 0.10,
        "tier_2_dark_pattern": 0.35,
        "tier_3_manipulative": 0.60,
        "tier_4_malicious": 0.85,
    }

    risk_tier = label.get("risk_tier", "tier_1_benign")
    tier_base = tier_base_map.get(risk_tier, 0.10)

    probability = tier_base
    tags = label.get("tags", {})

    increments = {
        "layer_4": 0.18,
        "layer_5": 0.10,
        "layer_3": 0.05,
        "layer_2": 0.03,
    }

    for layer_name in ["layer_4", "layer_5", "layer_3", "layer_2"]:
        layer_tags = tags.get(layer_name, [])

        if isinstance(layer_tags, str):
            layer_tags = [layer_tags]

        for _ in layer_tags:
            probability += increments[layer_name] * (1 - probability)

    probability = min(probability, 0.99)

    final_score = (probability * 100 * 0.7) + (tier_base * 100 * 0.3)

    return round(max(0, min(final_score, 100)))


def score_to_mailbox_targeted(score):
    if score < 25:
        return "benign"
    elif score < 50:
        return "dark pattern"
    elif score < 75:
        return "manipulative"
    else:
        return "malicious"


def recommendation_for(score):
    if score < 25:
        return "Mailbox appears mostly safe. Continue normal caution."
    elif score < 50:
        return "Some persuasive or dark-pattern emails are present. Review before clicking links."
    elif score < 75:
        return "Mailbox shows manipulative social engineering patterns. Verify senders and avoid quick actions."
    else:
        return "High-risk mailbox. Do not click links or open attachments until suspicious emails are reviewed."


def normalize_email(raw_email, index):
    if isinstance(raw_email, dict):
        return {
            "id": raw_email.get("id", f"email_{index}"),
            "to": raw_email.get("to", ""),
            "from": raw_email.get("from", ""),
            "subject": raw_email.get("subject", ""),
            "header": raw_email.get("header", ""),
            "encryption": raw_email.get("encryption", False),
            "body": raw_email.get("body", ""),
            "signature": raw_email.get("signature", ""),
            "attachment": raw_email.get("attachment", False),
        }

    return {
        "id": f"email_{index}",
        "to": "",
        "from": "",
        "subject": "",
        "header": "",
        "encryption": False,
        "body": str(raw_email),
        "signature": "",
        "attachment": False,
    }


if run_analysis:
    if not email_text.strip():
        st.warning("Paste an email or inbox first.")
    else:
        try:
            parsed = json.loads(email_text)

            if not isinstance(parsed, list):
                st.error("JSON input must be a list of emails.")
                st.stop()

            emails = [
                normalize_email(email, index)
                for index, email in enumerate(parsed, start=1)
            ]

        except json.JSONDecodeError:
            if "---" in email_text:
                email_bodies = [
                    email.strip()
                    for email in email_text.split("---")
                    if email.strip()
                ]

            elif re.search(r"\n\s*Subject:", email_text, re.IGNORECASE):
                parts = re.split(
                    r"\n\s*(?=Subject:)",
                    email_text,
                    flags=re.IGNORECASE
                )

                email_bodies = [
                    email.strip()
                    for email in parts
                    if email.strip()
                ]

            else:
                email_bodies = [email_text.strip()]

            emails = [
                normalize_email(body, index)
                for index, body in enumerate(email_bodies, start=1)
            ]

        st.write(f"Detected emails: {len(emails)}")

        all_labels = []
        batch_outputs = []

        batches = list(chunk_list(emails, BATCH_SIZE))
        progress = st.progress(0)

        with st.spinner("Analyzing inbox in batches..."):
            for batch_index, batch in enumerate(batches, start=1):
                st.write(f"Running batch {batch_index} / {len(batches)}")

                model_input = {
                    "emails": batch
                }

                batch_labels = analyze_email(model_input)

                if isinstance(batch_labels, dict):
                    batch_labels = [batch_labels]

                batch_outputs.append(batch_labels)
                all_labels.extend(batch_labels)

                progress.progress(batch_index / len(batches))

        email_scores = [score_label(label) for label in all_labels]

        if email_scores:
            average_score = sum(email_scores) / len(email_scores)
            max_score = max(email_scores)
            risk_score = round((average_score * 0.6) + (max_score * 0.4))
        else:
            risk_score = 0

        domain_counts = Counter()
        layer_counts = Counter()

        for label in all_labels:
            domain = label.get("domain_tag")
            if domain:
                domain_counts[domain] += 1

            tags = label.get("tags", {})
            for layer_name in ["layer_2", "layer_3", "layer_4", "layer_5"]:
                layer_tags = tags.get(layer_name, [])

                if isinstance(layer_tags, str):
                    layer_tags = [layer_tags]

                for tag in layer_tags:
                    layer_counts[tag] += 1

        most_common_domain = domain_counts.most_common(1)
        most_common_layer = layer_counts.most_common(1)

        most_received_emails = most_common_domain[0][0] if most_common_domain else "none"
        mailbox_targeted = score_to_mailbox_targeted(risk_score)
        recommendation = recommendation_for(risk_score)

        final_result = {
            "risk score": risk_score,
            "most received emails": most_received_emails,
            "mailbox targeted": mailbox_targeted,
            "recommendation": recommendation,
            "email_scores": email_scores,
            "labels": all_labels,
            "most_common_layer_tag": most_common_layer[0] if most_common_layer else ("none", 0),
            "batch_outputs": batch_outputs
        }

        st.subheader("Inbox Output")

        col1, col2, col3 = st.columns(3)

        col1.metric("Risk Score", final_result["risk score"])
        col2.metric("Mailbox Targeted", final_result["mailbox targeted"])
        col3.metric("Emails Scored", len(email_scores))

        col4, col5 = st.columns(2)

        col4.metric("Most Received Emails", final_result["most received emails"])

        layer_name, layer_count = final_result["most_common_layer_tag"]
        col5.metric("Most Common Layer Tag", f"{layer_name} ({layer_count})")

        st.write("Recommendation:")
        st.write(final_result["recommendation"])

        st.subheader("Individual Email Scores")

        for i, score in enumerate(email_scores, start=1):
            st.write(f"Email {i}: {score}")

        st.subheader("Raw Output")
        st.json(final_result)