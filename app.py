import streamlit as st
from model_runner import analyze_email

st.set_page_config(page_title="Email Risk Analyzer", layout="wide")

st.title("Email Social Engineering Risk Analyzer")
st.caption("Demo UI for emails → model → score + recommendation")

st.header("1. Input")

input_mode = st.radio(
    "Choose input method",
    ["Paste email text", "Upload inbox file"],
    horizontal=True
)

email_text = ""

if input_mode == "Paste email text":
    email_text = st.text_area("Paste email content here", height=220)
else:
    uploaded_file = st.file_uploader("Upload inbox file", type=["json", "csv", "txt"])

    if uploaded_file is not None:
        email_text = uploaded_file.read().decode("utf-8", errors="ignore")
        st.success("File uploaded successfully.")

st.header("2. Analysis")

st.write("When connected, this button will send the email data to the model and return risk scoring.")

run_analysis = st.button("Run Analysis")

st.header("3. Results")

if run_analysis:
    if not email_text.strip():
        st.warning("Please paste an email or upload a file before running analysis.")
    else:
        result = analyze_email(email_text)

        risk_score = result["risk_score"]
        risk_level = result["risk_level"]
        flagged_emails = result["flagged_emails"]

        st.subheader("Inbox Risk Summary")

        col1, col2, col3 = st.columns(3)
        col1.metric("Inbox Risk Score", f"{risk_score}/100")
        col2.metric("Risk Level", risk_level)
        col3.metric("Flagged Emails", flagged_emails)

        st.subheader("Recommendation")

        if risk_score >= 80:
            st.error("Recommendation: Do not interact with this email. Treat it as highly suspicious.")
        elif risk_score >= 60:
            st.warning("Recommendation: Review carefully before clicking links, opening attachments, or replying.")
        elif risk_score >= 35:
            st.info("Recommendation: Some suspicious signals were found. Verify the sender before acting.")
        else:
            st.success("Recommendation: Low risk based on available signals.")

        st.subheader("Flagged Email Breakdown")

        st.write("Model output will appear here after integration.")

        st.dataframe(
            {
                "Email": ["Email 1"],
                "Risk Score": [risk_score],
                "Risk Level": [risk_level],
                "Reason": ["Placeholder: suspicious language, urgency, or links detected"],
                "Recommendation": ["Verify sender before interacting"]
            }
        )

else:
    st.info("Paste an email or upload a file, then click Run Analysis.")