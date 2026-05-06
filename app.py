import streamlit as st
import json
import re
from collections import Counter
from model_runner import analyze_email

BATCH_SIZE = 5

if "analysis_complete" not in st.session_state:
    st.session_state.analysis_complete = False

if "emails" not in st.session_state:
    st.session_state.emails = []

if "all_labels" not in st.session_state:
    st.session_state.all_labels = []

if "email_scores" not in st.session_state:
    st.session_state.email_scores = []

if "risk_score" not in st.session_state:
    st.session_state.risk_score = 0

if "max_score" not in st.session_state:
    st.session_state.max_score = 0

if "most_received_emails" not in st.session_state:
    st.session_state.most_received_emails = "none"

if "most_common_layer" not in st.session_state:
    st.session_state.most_common_layer = ("none", 0)

if "mailbox_targeted" not in st.session_state:
    st.session_state.mailbox_targeted = "Benign"

if "recommendation" not in st.session_state:
    st.session_state.recommendation = ""

st.set_page_config(
    page_title="HowsMyEmail",
    page_icon="📧",
    layout="wide"
)

st.markdown("""
<style>
    .main-title {
        font-size: 2.4rem;
        font-weight: 800;
        margin-bottom: 0rem;
    }

    .subtitle {
        font-size: 1rem;
        color: #6c757d;
        margin-bottom: 1.5rem;
    }

    .portal-card {
        background-color: #ffffff;
        color: #212529;
        padding: 1.2rem;
        border-radius: 16px;
        border: 1px solid #e6e6e6;
        box-shadow: 0px 2px 8px rgba(0,0,0,0.04);
        margin-bottom: 1rem;
    }

    .assessment-benign {
        color: #198754;
        font-weight: 800;
    }

    .assessment-dark-pattern {
        color: #b58100;
        font-weight: 800;
    }

    .assessment-manipulative {
        color: #fd7e14;
        font-weight: 800;
    }

    .assessment-malicious {
        color: #dc3545;
        font-weight: 800;
    }

    .risk-tile {
        display: inline-block;
        width: 14px;
        height: 14px;
        border-radius: 4px;
        margin-right: 8px;
        vertical-align: middle;
    }

    .tile-benign {
        background-color: #198754;
    }

    .tile-dark-pattern {
        background-color: #b58100;
    }

    .tile-manipulative {
        background-color: #fd7e14;
    }

    .tile-malicious {
        background-color: #dc3545;
    }

    .tag-pill {
        display: inline-block;
        padding: 0.25rem 0.55rem;
        margin: 0.15rem;
        border-radius: 999px;
        background-color: #f1f3f5;
        border: 1px solid #dee2e6;
        font-size: 0.85rem;
        color: #212529;
    }

    .email-preview {
        background-color: #f8f9fa;
        color: #212529;
        padding: 0.8rem;
        border-radius: 10px;
        border: 1px solid #eeeeee;
        margin-top: 0.5rem;
        max-height: 220px;
        overflow-y: auto;
        white-space: pre-wrap;
    }
</style>
""", unsafe_allow_html=True)


def chunk_list(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def score_label(label):
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
            layer_tags = [{"tag": layer_tags}]

        for tag_item in layer_tags:
            if tag_item:
                probability += increments[layer_name] * (1 - probability)

    probability = min(probability, 0.99)
    final_score = (probability * 100 * 0.7) + (tier_base * 100 * 0.3)

    return round(max(0, min(final_score, 100)))


def score_to_mailbox_targeted(score):
    if score < 25:
        return "Benign"
    elif score < 50:
        return "Dark Pattern"
    elif score < 75:
        return "Manipulative"
    else:
        return "Malicious"


def recommendation_for(score):
    if score < 25:
        return "Mailbox appears mostly safe. Continue normal caution."
    elif score < 50:
        return "Some persuasive or dark-pattern emails are present. Review before clicking links."
    elif score < 75:
        return "Mailbox shows manipulative social engineering patterns. Verify senders and avoid quick actions."
    else:
        return "High-risk mailbox. Do not click links or open attachments until suspicious emails are reviewed."


def assessment_class(score):
    if score < 25:
        return "assessment-benign"
    elif score < 50:
        return "assessment-dark-pattern"
    elif score < 75:
        return "assessment-manipulative"
    else:
        return "assessment-malicious"


def tile_class(score):
    if score < 25:
        return "tile-benign"
    elif score < 50:
        return "tile-dark-pattern"
    elif score < 75:
        return "tile-manipulative"
    else:
        return "tile-malicious"


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


def parse_input(email_text):
    try:
        parsed = json.loads(email_text)

        if not isinstance(parsed, list):
            st.error("JSON input must be a list of emails.")
            st.stop()

        return [
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

        return [
            normalize_email(body, index)
            for index, body in enumerate(email_bodies, start=1)
        ]


def get_layer_tags(label, layer_name):
    tags = label.get("tags", {}).get(layer_name, [])

    if isinstance(tags, str):
        return [{"tag": tags, "description": "", "reason": ""}]

    cleaned_tags = []

    for item in tags:
        if isinstance(item, dict):
            cleaned_tags.append({
                "tag": item.get("tag", ""),
                "description": item.get("description", ""),
                "reason": item.get("reason", "")
            })
        else:
            cleaned_tags.append({
                "tag": str(item),
                "description": "",
                "reason": ""
            })

    return cleaned_tags


def display_tag_section(label, layer_name, title):
    tags = get_layer_tags(label, layer_name)

    if not tags:
        return

    st.markdown(f"**{title}**")

    for tag_item in tags:
        tag = tag_item.get("tag", "")
        description = tag_item.get("description", "")
        reason = tag_item.get("reason", "")

        if tag:
            st.markdown(f"<span class='tag-pill'>{tag}</span>", unsafe_allow_html=True)

        if description:
            st.caption(description)

        if reason:
            st.write(f"Why it applied: {reason}")


st.markdown("<div class='main-title'>HowsMyEmail</div>", unsafe_allow_html=True)
st.markdown(
    "<div class='subtitle'>Inbox Social Engineering Risk Portal</div>",
    unsafe_allow_html=True
)

with st.sidebar:
    st.header("Inbox Scanner")

    with st.expander("Input Options", expanded=True):
        st.write("Paste a JSON list, upload a JSON/TXT file, or use plain-text emails separated by `---`.")

        uploaded_file = st.file_uploader(
            "Upload Inbox File",
            type=["json", "txt"],
            help="Upload a .json file with email objects or a .txt file with plain email text."
        )

        uploaded_text = ""

        if uploaded_file is not None:
            uploaded_text = uploaded_file.read().decode("utf-8")

        email_text = st.text_area(
            "Inbox Input",
            value=uploaded_text,
            height=260,
            placeholder='[{"to": "", "from": "", "subject": "", "body": "", "attachment": false}]'
        )

        run_analysis = st.button(
            "Run Inbox Analysis",
            use_container_width=True
        )

    show_email_reviews = st.toggle(
        "Show per-email reviews",
        value=False
    )

    with st.expander("Per-Email Risk Key", expanded=False):
        st.markdown("<span class='risk-tile tile-benign'></span> Benign", unsafe_allow_html=True)
        st.markdown("<span class='risk-tile tile-dark-pattern'></span> Dark Pattern", unsafe_allow_html=True)
        st.markdown("<span class='risk-tile tile-manipulative'></span> Manipulative", unsafe_allow_html=True)
        st.markdown("<span class='risk-tile tile-malicious'></span> Malicious", unsafe_allow_html=True)

    with st.expander("Accepted Input", expanded=False):
        st.write("Uploaded `.json` file")
        st.write("Uploaded `.txt` file")
        st.write("JSON list of email objects")
        st.write("Plain text emails separated by `---`")
        st.write("Plain text emails starting with `Subject:`")

st.markdown("### Dashboard")

if run_analysis:
    if not email_text.strip():
        st.warning("Paste or upload an email inbox first.")
        st.stop()

    emails = parse_input(email_text)

    all_labels = []
    batches = list(chunk_list(emails, BATCH_SIZE))

    progress = st.progress(0)

    with st.spinner("Scanning inbox for social engineering signals..."):
        for batch_index, batch in enumerate(batches, start=1):
            model_input = {
                "emails": batch
            }

            batch_labels = analyze_email(model_input)

            if isinstance(batch_labels, dict):
                batch_labels = [batch_labels]

            all_labels.extend(batch_labels)
            progress.progress(batch_index / len(batches))

    email_scores = [score_label(label) for label in all_labels]

    if email_scores:
        average_score = sum(email_scores) / len(email_scores)
        max_score = max(email_scores)
        risk_score = round((average_score * 0.6) + (max_score * 0.4))
    else:
        risk_score = 0
        max_score = 0

    domain_counts = Counter()
    layer_counts = Counter()

    for label in all_labels:
        domain = label.get("domain_tag")

        if domain:
            domain_counts[domain] += 1

        for layer_name in ["layer_2", "layer_3", "layer_4", "layer_5"]:
            for tag_item in get_layer_tags(label, layer_name):
                tag_name = tag_item.get("tag")

                if tag_name:
                    layer_counts[tag_name] += 1

    most_common_domain = domain_counts.most_common(1)
    most_common_layer = layer_counts.most_common(1)

    most_received_emails = most_common_domain[0][0] if most_common_domain else "none"
    mailbox_targeted = score_to_mailbox_targeted(risk_score)
    recommendation = recommendation_for(risk_score)

    st.session_state.emails = emails
    st.session_state.all_labels = all_labels
    st.session_state.email_scores = email_scores
    st.session_state.risk_score = risk_score
    st.session_state.max_score = max_score
    st.session_state.most_received_emails = most_received_emails
    st.session_state.most_common_layer = most_common_layer[0] if most_common_layer else ("none", 0)
    st.session_state.mailbox_targeted = mailbox_targeted
    st.session_state.recommendation = recommendation
    st.session_state.analysis_complete = True

if not st.session_state.analysis_complete:
    st.info("Paste or upload an inbox in the sidebar and run the analysis to view the security dashboard.")
    st.stop()

emails = st.session_state.emails
all_labels = st.session_state.all_labels
email_scores = st.session_state.email_scores
risk_score = st.session_state.risk_score
max_score = st.session_state.max_score
most_received_emails = st.session_state.most_received_emails
layer_name, layer_count = st.session_state.most_common_layer
mailbox_targeted = st.session_state.mailbox_targeted
recommendation = st.session_state.recommendation

st.markdown(
    f"<div class='portal-card'><b>Detected Emails:</b> {len(emails)}</div>",
    unsafe_allow_html=True
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Risk Score", risk_score)
col2.metric("Highest Email Score", max_score)
col3.metric("Mailbox Category", mailbox_targeted)
col4.metric("Most Common Domain", most_received_emails)

col5 = st.columns(1)[0]
col5.metric("Most Common Tag", f"{layer_name} ({layer_count})")

st.markdown("### Recommendation")

st.markdown(
    f"""
    <div class='portal-card'>
        <div class='{assessment_class(risk_score)}'>Mailbox Assessment: {mailbox_targeted}</div>
        <p>{recommendation}</p>
    </div>
    """,
    unsafe_allow_html=True
)

if show_email_reviews:
    st.markdown("### Individual Email Breakdown")
    st.metric("Emails Reviewed", len(email_scores))

    for index, email in enumerate(emails, start=1):
        label = all_labels[index - 1] if index - 1 < len(all_labels) else {}
        score = email_scores[index - 1] if index - 1 < len(email_scores) else 0

        subject = email.get("subject") or f"Email {index}"
        sender = email.get("from") or "Unknown sender"
        body = email.get("body") or ""

        risk_tier = label.get("risk_tier", "unknown")
        domain_tag = label.get("domain_tag", "unknown")
        risk_summary = label.get("risk_summary", "No summary returned.")

        expander_title = f"Email {index}: {subject} — Score {score}"

        st.markdown(
            f"<span class='risk-tile {tile_class(score)}'></span><b>{expander_title}</b>",
            unsafe_allow_html=True
        )

        with st.expander("View details", expanded=False):
            top_a, top_b, top_c = st.columns(3)

            top_a.metric("Email Score", score)
            top_b.metric("Risk Tier", risk_tier)
            top_c.metric("Domain", domain_tag)

            st.markdown("**Sender**")
            st.write(sender)

            st.markdown("**Risk Summary**")
            st.write(risk_summary)

            st.markdown("**Email Preview**")
            st.markdown(
                f"<div class='email-preview'>{body}</div>",
                unsafe_allow_html=True
            )

            st.divider()

            display_tag_section(label, "layer_2", "Layer 2: Scenario / Attack Type")
            display_tag_section(label, "layer_3", "Layer 3: Persuasion Technique")
            display_tag_section(label, "layer_4", "Layer 4: Harmful Outcome")
            display_tag_section(label, "layer_5", "Layer 5: Delivery / Infrastructure Signal")
else:
    st.info(
        f"{len(email_scores)} emails reviewed. Enable per-email review in the sidebar to inspect individual messages."
    )