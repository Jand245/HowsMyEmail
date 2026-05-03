import streamlit as st
from model_runner import analyze_email

st.set_page_config(page_title="Email Risk Analyzer", layout="wide")

st.title("Email Social Engineering Risk Analyzer")
st.caption("Demo UI for email input , model output , risk score and recommendation")

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
    uploaded_file = st.file_uploader(
        "Upload inbox file",
        type=["json", "csv", "txt"]
    )

    if uploaded_file is not None:
        email_text = uploaded_file.read().decode("utf-8", errors="ignore")
        st.success("File uploaded successfully.")

model_input = {
    "to": "",
    "from": "",
    "subject": "",
    "header": "",
    "encryption": False,
    "body": email_text,
    "signature": "",
    "attachment": False
}

st.header("2. Analysis")

run_analysis = st.button("Run Analysis")

st.header("3. Results")

if run_analysis:
    if not email_text.strip():
        st.warning("Please paste an email or upload a file before running analysis.")
    else:
        try:
            result = analyze_email(model_input)

            risk_score = result.get("risk_score", "N/A")
            most_received_emails = result.get("most_received_emails", "N/A")
            mailbox_targeted = result.get("mailbox_targeted", "N/A")
            recommendation = result.get("recommendation", "No recommendation provided.")

            st.subheader("Mailbox Risk Summary")

            col1, col2, col3 = st.columns(3)
            col1.metric("Risk Score", f"{risk_score}/100")
            col2.metric("Most Received Emails", most_received_emails)
            col3.metric("Mailbox Targeted", mailbox_targeted)

            st.subheader("Recommendation")
            st.info(recommendation)

            st.subheader("Raw Model Output")
            st.json(result)

        except Exception as e:
            st.error("Model analysis failed.")
            st.exception(e)
else:
    st.info("Paste an email or upload a file, then click Run Analysis.")