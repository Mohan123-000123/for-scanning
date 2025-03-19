import os
import imaplib
import email
from email.header import decode_header
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer

# 1. Load the trained model and vectorizer
model_path = "C:/Users/mohan/OneDrive/Documents/Downloads/phishing_detection_model.joblib"
vectorizer_path = "C:/Users/mohan/OneDrive/Documents/Downloads/vectorizer.joblib"

# Load the model and vectorizer
model = joblib.load(model_path)
vectorizer = joblib.load(vectorizer_path)

# Get email user and password from environment variables
email_user = os.environ.get('EMAIL_USER')
email_password = os.environ.get('EMAIL_PASSWORD')

# Ensure email credentials are loaded
if not email_user or not email_password:
    raise ValueError("Email credentials not set in environment variables")

# 2. Function to clean the email content
def clean_email_content(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" not in content_disposition:
                # Get the email body
                body = part.get_payload(decode=True).decode()
                if content_type == "text/plain":
                    return body
    else:
        body = msg.get_payload(decode=True).decode()
        return body

# 3. Connect to your email account using IMAP
imap_url = "imap.gmail.com"  # Change this for your email provider

try:
    # Establish connection to the IMAP server
    mail = imaplib.IMAP4_SSL(imap_url)
    mail.login(email_user, email_password)
except imaplib.IMAP4.error as e:
    print(f"IMAP login failed: {e}")
    exit(1)

# Select the mailbox you want to use (INBOX)
mail.select("inbox")

# Search for all emails (you can modify this to search for unread emails)
status, messages = mail.search(None, "ALL")
messages = messages[0].split()

# 4. Process each email
for mail_id in messages:
    # Fetch the email by ID
    status, msg_data = mail.fetch(mail_id, "(RFC822)")
    for response_part in msg_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])

            # Decode the email subject
            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding if encoding else "utf-8")
            
            # Extract the email content
            body = clean_email_content(msg)
            
            # Preprocess the content using the vectorizer
            X_new = vectorizer.transform([body])
            
            # Make prediction using the loaded model
            prediction = model.predict(X_new)[0]
            
            # Print the result
            if prediction == 1:
                print(f"📧 Phishing Email Detected: {subject}")
            else:
                print(f"📧 Legitimate Email: {subject}")

# Close the connection and logout
mail.close()
mail.logout()
