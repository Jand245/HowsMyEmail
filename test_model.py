print("Starting test...")

from model_runner import analyze_email

print("Imported model_runner...")

test_input = {
    "emails": [
        {
            "body": "Your account will be suspended in 24 hours. Click here to verify your password immediately."
        }
    ]
}

print("Calling model...")

result = analyze_email(test_input)

print("\n=== RESULT ===")
print(result)
print("Done.")