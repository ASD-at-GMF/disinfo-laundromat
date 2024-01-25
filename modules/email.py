import smtplib
from email.message import EmailMessage
import pandas as pd
from config import EMAIL_CREDS

sender_email = EMAIL_CREDS['username']
password = EMAIL_CREDS['app_password']

def send_results_email(
    receiver_email: str,
    subject: str,
    body: str,
    csv_filename: str,
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

    # Open the file in binary mode
    with open(csv_filename, 'rb') as attachment:
        # Add file as application/octet-stream
        # Email client can usually download this automatically as attachment
        msg.add_attachment(attachment.read(), maintype='application', subtype='octet-stream', filename='disinfo_laundromat_results.csv')

    # Send the email
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, password)
            server.send_message(msg)
        print("Email sent successfully")
    except Exception as e:
        print(f"Error sending email: {e}")
