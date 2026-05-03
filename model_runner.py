def analyze_email(email_text):
    """
    Temporary model interface.
    Later, replace the fake values with real classifier output.
    """

    return {
        "risk_score": 72,
        "risk_level": "High",
        "flagged_emails": 1,
        "recommendation": "Review carefully before clicking links, opening attachments, or replying.",
        "breakdown": [
            {
                "email": "Email 1",
                "risk_score": 72,
                "risk_level": "High",
                "reason": "Placeholder: suspicious language, urgency, or links detected",
                "recommendation": "Verify sender before interacting"
            }
        ]
    }