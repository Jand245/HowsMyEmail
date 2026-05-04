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


def score_to_tier(score):
    if score < 25:
        return "tier_1_benign"
    elif score < 50:
        return "tier_2_dark_pattern"
    elif score < 75:
        return "tier_3_manipulative"
    else:
        return "tier_4_malicious"


if run_analysis:
    if not email_text.strip():
        st.warning("Paste an email or inbox first.")
    else:
        try:
            emails = json.loads(email_text)

            if not isinstance(emails, list):
                st.error("JSON input must be a list of emails.")
                st.stop()

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
                email_bodies = [
                    email_text.strip()
                ]

            emails = []

            for body in email_bodies:
                emails.append(
                    {
                        "to": "",
                        "from": "",
                        "subject": "",
                        "header": "",
                        "encryption": False,
                        "body": body,
                        "signature": "",
                        "attachment": False
                    }
                )

        st.write(f"Detected emails: {len(emails)}")

        all_email_scores = []
        all_email_results = []
        batch_outputs = []

        batches = list(chunk_list(emails, BATCH_SIZE))

        progress = st.progress(0)

        with st.spinner("Analyzing inbox in batches..."):
            for batch_index, batch in enumerate(batches, start=1):
                st.write(f"Running batch {batch_index} / {len(batches)}")

                model_input = {
                    "emails": batch
                }

                batch_result = analyze_email(model_input)
                batch_outputs.append(batch_result)

                batch_scores = batch_result.get("email_scores", [])
                batch_results = batch_result.get("email_results", [])

                all_email_scores.extend(batch_scores)
                all_email_results.extend(batch_results)

                progress.progress(batch_index / len(batches))

        if all_email_scores:
            average_score = sum(all_email_scores) / len(all_email_scores)
            max_score = max(all_email_scores)

            inbox_score = round((average_score * 0.6) + (max_score * 0.4))
            inbox_tier = score_to_tier(inbox_score)

        else:
            inbox_score = 0
            inbox_tier = "unknown"

        domain_counts = Counter()
        layer_counts = Counter()

        for email_result in all_email_results:
            domain = email_result.get("domain_tag")
            if domain:
                domain_counts[domain] += 1

            for layer_name in ["layer_2", "layer_3", "layer_4", "layer_5"]:
                tags = email_result.get(layer_name, [])

                if isinstance(tags, str):
                    tags = [tags]

                for tag in tags:
                    layer_counts[tag] += 1

        most_common_domain = domain_counts.most_common(1)
        most_common_layer = layer_counts.most_common(1)

        final_result = {
            "risk_tier": inbox_tier,
            "inbox_score": inbox_score,
            "email_scores": all_email_scores,
            "most_common_domain": most_common_domain[0] if most_common_domain else ("none", 0),
            "most_common_layer_tag": most_common_layer[0] if most_common_layer else ("none", 0),
            "reason": f"Scored {len(all_email_scores)} emails in batches of {BATCH_SIZE}. Final inbox score uses 60% average risk and 40% highest email risk.",
            "batch_outputs": batch_outputs
        }

        st.subheader("Inbox Output")

        col1, col2, col3 = st.columns(3)

        col1.metric("Inbox Risk Tier", final_result["risk_tier"])
        col2.metric("Inbox Score", final_result["inbox_score"])
        col3.metric("Emails Scored", len(all_email_scores))

        col4, col5 = st.columns(2)

        domain_name, domain_count = final_result["most_common_domain"]
        layer_name, layer_count = final_result["most_common_layer_tag"]

        col4.metric("Most Common Domain", f"{domain_name} ({domain_count})")
        col5.metric("Most Common Layer Tag", f"{layer_name} ({layer_count})")

        st.write("Reason:")
        st.write(final_result["reason"])

        st.subheader("Individual Email Scores")

        for i, score in enumerate(all_email_scores, start=1):
            st.write(f"Email {i}: {score}")

        st.subheader("Raw Output")
        st.json(final_result)