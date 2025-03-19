import joblib
import pandas as pd
import re
import mysql.connector
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
import imaplib
import email
from plyer import notification
import tkinter as tk
from tkinter import messagebox

# 📌 Database Connection
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",  # No password by default in XAMPP
    database="phishing_detector"
)
cursor = conn.cursor()

# 📌 Extract URLs from Email Body
def extract_urls(text):
    url_pattern = r'(https?://\S+)'  # Regex for detecting URLs
    return re.findall(url_pattern, text)

# 📌 Store Phishing Email in Database
def store_phishing_email(subject, sender, urls):
    urls_str = ', '.join(urls)  # Convert list of URLs to a string
    query = "INSERT INTO phishing_emails (subject, sender, urls) VALUES (%s, %s, %s)"
    cursor.execute(query, (subject, sender, urls_str))
    conn.commit()

# 📌 Extract Email Body
def get_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors='ignore')
    else:
        return msg.get_payload(decode=True).decode(errors='ignore')
    return ""

# 📌 Connect to Email Server
def connect_email(gmail_id, app_password):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(gmail_id, app_password)
        return mail
    except Exception as e:
        print(f"Error connecting to email server: {e}")
        return None

# 📌 Check Emails and Detect Phishing
def check_emails(model, vectorizer, checked_email_ids, gmail_id, app_password, status_label, scan_button):
    mail = connect_email(gmail_id, app_password)
    if not mail:
        status_label.config(text="Failed to connect to email server.")
        return

    mail.select("inbox")
    _, data = mail.search(None, "UNSEEN")
    email_ids = data[0].split()

    phishing_count = 0
    status_label.config(text="Scanning emails... Please wait.")

    for email_id in email_ids:
        if email_id.decode() in checked_email_ids:
            continue

        _, msg_data = mail.fetch(email_id, "(RFC822)")

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject = msg["subject"]
                sender = msg["from"]
                body = get_email_body(msg)

                email_vectorized = vectorizer.transform([body])
                prediction = model.predict(email_vectorized)[0]

                label_text = "🚨 Phishing Email!" if prediction == 1 else "✅ Safe Email"

                if label_text == "🚨 Phishing Email!":
                    phishing_count += 1
                    urls = extract_urls(body)
                    store_phishing_email(subject, sender, urls)  # Store in DB

                show_notification(subject, sender, label_text)
                checked_email_ids.add(email_id.decode())

    status_label.config(text=f"Scan Complete\nPhishing emails detected: {phishing_count}")
    scan_button.config(state=tk.NORMAL)
    mail.logout()

# 📌 Show System Notification
def show_notification(subject, sender, label_text):
    message = f"From: {sender}\nSubject: {subject}\nStatus: {label_text}"
    notification.notify(
        title="📧 Email Scan Result",
        message=message,
        timeout=5
    )
    if label_text == "🚨 Phishing Email!":
        messagebox.showwarning("Phishing Alert", f"Phishing Email Detected!\nFrom: {sender}\nSubject: {subject}")
    else:
        messagebox.showinfo("Safe Email", f"Safe Email\nFrom: {sender}\nSubject: {subject}")

# 📌 GUI for Email Scanning
def create_gui(model, vectorizer):
    window = tk.Tk()
    window.title("Phishing Email Detector")
    window.geometry("400x300")

    status_label = tk.Label(window, text="Enter Gmail ID and App Password", font=("Arial", 14))
    status_label.pack(pady=20)

    email_label = tk.Label(window, text="Gmail ID:")
    email_label.pack()
    email_entry = tk.Entry(window, font=("Arial", 12))
    email_entry.pack(pady=5)

    password_label = tk.Label(window, text="App Password:")
    password_label.pack()
    password_entry = tk.Entry(window, font=("Arial", 12), show="*")
    password_entry.pack(pady=5)

    checked_email_ids = set()

    def start_email_scan():
        gmail_id = email_entry.get()
        app_password = password_entry.get()
        if not gmail_id or not app_password:
            messagebox.showerror("Input Error", "Please enter both Gmail ID and App Password!")
            return

        status_label.config(text="Scanning for phishing emails...")
        scan_button.config(state=tk.DISABLED)
        check_emails(model, vectorizer, checked_email_ids, gmail_id, app_password, status_label, scan_button)

    scan_button = tk.Button(window, text="Scan Email", font=("Arial", 12), command=start_email_scan)
    scan_button.pack(pady=20)

    window.mainloop()

# 📌 Main Execution
if __name__ == "__main__":
    model = joblib.load("phishing_detection_model.joblib")
    vectorizer = joblib.load("vectorizer.joblib")
    create_gui(model, vectorizer)

# 📌 Close DB Connection on Exit
conn.close()

