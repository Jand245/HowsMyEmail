import streamlit as st
from model_runner import analyze_email

st.set_page_config(page_title="HowsMyEmail", layout="wide")

st.title("HowsMyEmail")
st.caption("Demo interface for analyzing email social engineering risk")

st.header("1. Input")

email_text = st.text_area("Paste email content here", height=250)

st.header("2. Analysis")

st.write("The local model connects through `model_runner.py`.")

run_analysis = st.button("Run Analysis")

st.header("3. Results")

if run_analysis:
    if not email_text.strip():
        st.warning("Paste an email first.")
    else:
        model_input = {
            "emails": [
                {
                    "to": "",
                    "from": "",
                    "subject": "",
                    "header": "",
                    "encryption": False,
                    "body": email_text,
                    "signature": "",
                    "attachment": False
                }
            ]
        }

        with st.spinner("Analyzing email..."):
            result = analyze_email(model_input)

        st.subheader("Model Output")

        col1, col2 = st.columns(2)

        col1.metric("Risk Tier", result.get("risk_tier", "unknown"))
        col2.metric("Confidence", result.get("confidence", 0))

        st.write("Reason:")
        st.write(result.get("reason", ""))

        st.subheader("Raw Output")
        st.json(result)