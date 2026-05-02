import streamlit as st

st.set_page_config(page_title="Email Risk Analyzer", layout="wide")

st.title("Email Social Engineering Risk Analyzer")
st.caption("Early demo layout for inbox-level social engineering risk analysis")

st.header("1. Input")

input_mode = st.radio(
    "Choose a possible input method",
    ["Paste email text", "Upload inbox file"],
    horizontal=True
)

if input_mode == "Paste email text":
    pasted_email = st.text_area("Paste email content here", height=200)
else:
    uploaded_file = st.file_uploader("Upload inbox file", type=["json", "csv", "txt"])

st.header("2. Analysis")

st.write("This section can connect to the model once the input/output format is finalized.")

run_analysis = st.button("Run Analysis")

st.header("3. Results")

if run_analysis:
    st.subheader("Possible Inbox Risk Summary")

    col1, col2, col3 = st.columns(3)
    col1.metric("Inbox Risk Score", "TBD")
    col2.metric("Risk Level", "TBD")
    col3.metric("Flagged Emails", "TBD")

    st.info("This area can display model output after integration.")

    st.subheader("Possible Flagged Email Breakdown")

    st.write("This section can show per-email scores, labels, and explanations.")

else:
    st.info("Results area placeholder.")