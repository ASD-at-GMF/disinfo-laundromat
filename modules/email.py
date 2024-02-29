import smtplib
from email.message import EmailMessage
import pandas as pd
import os 
from io import BytesIO
EMAIL_CREDS_USER = os.getenv('EMAIL_CREDS_USER')
EMAIL_CREDS_PASS = os.getenv('EMAIL_CREDS_PASS')
EMAIL_CREDS_SMTP = os.getenv('EMAIL_CREDS_SMTP')



def send_results_email(receiver_email, subject, body, file, filename = "none"
    ):
    """
    Send an email with a CSV file as an attachment.
    """
    # Create a multipart message
    msg = EmailMessage()
    msg["From"] = EMAIL_CREDS_USER
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
        with smtplib.SMTP_SSL(EMAIL_CREDS_SMTP, 465) as server:
            server.login(EMAIL_CREDS_USER, EMAIL_CREDS_PASS)
            server.send_message(msg)
        print("Email sent successfully")
    except Exception as e:
        print(f"Error sending email: {e}")
