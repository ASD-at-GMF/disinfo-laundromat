import smtplib
from email.message import EmailMessage
import pandas as pd
from config import EMAIL_CREDS
from io import BytesIO

sender_email = EMAIL_CREDS['username']
password = EMAIL_CREDS['app_password']

def send_results_email(receiver_email, subject, body, file, filename = "none"
    ):
    """
    Send an email with a CSV file as an attachment.
    """
    # Create a multipart message
    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.set_content(body)

    print(filename)
    # Check if csv_file is a file-like object
    if isinstance(file, BytesIO):
        # Make sure we're at the start of the BytesIO object
        file.seek(0)
        # Read the content of the file-like object
        attachment_content = file.read()
        msg.add_attachment(attachment_content, maintype='application', subtype='octet-stream', filename=filename)
   
    # Send the email
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, password)
            server.send_message(msg)
        print("Email sent successfully")
    except Exception as e:
        print(f"Error sending email: {e}")
