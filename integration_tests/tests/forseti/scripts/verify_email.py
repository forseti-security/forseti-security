import argparse
import pickle
import os.path
import time

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# If modifying these scopes, delete the file gmail_token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def get_service(pickle_path):
    """Create the Gmail client service.

    Args:
        pickle_path (str): Path to the pickle file.

    Returns:
        Service: Returns the Gmail client service.
    """
    credentials = None

    # The file gmail_token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists(pickle_path):
        with open(pickle_path, 'rb') as token:
            credentials = pickle.load(token)

    # If there are no (valid) credentials available, let the user log in.
    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json',
                SCOPES)
            credentials = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(pickle_path, 'wb') as token:
            pickle.dump(credentials, token)

    service = build('gmail', 'v1', credentials=credentials)
    return service


def verify_email(after_timestamp, pickle_path, retries, sender, subject):
    """Verify email has been received by Gmail account.

    Args:
        after_timestamp (str): Timestamp to check for emails after.
        pickle_path (str): Path to the pickle file.
        retries (int): Number of retries to attempt.
        sender (str): Sender of the email.
        subject (str): Subject of the email.

    Returns:
        int: Return the number of emails found.
    """
    query = []
    service = get_service(pickle_path)

    if after_timestamp:
        query.append("after:" + after_timestamp)

    if sender:
        query.append("from:(" + sender + ")")

    if subject:
        query.append("subject:(" + subject + ")")

    # Call the Gmail API
    while retries > 0:
        response = service.users().messages().list(userId='me', q=" ".join(query)).execute()
        if 'messages' in response:
            return len(response['messages'])
        retries -= 1
        time.sleep(5)

    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Confirms that a gmail '
                                                 'email exist')
    parser.add_argument('--after_timestamp', default=None, help='after timestamp')
    parser.add_argument('--pickle_path',
                        type=str,
                        default='token.pickle',
                        help='Path to pickle file')
    parser.add_argument('--retries', default=1, help='retries', type=int)
    parser.add_argument('--sender', default='', help='from', type=str)
    parser.add_argument('--subject', default='', help='subject', type=str)
    args = parser.parse_args()

    email_count = verify_email(args.after_timestamp,
                               args.pickle_path,
                               args.retries,
                               args.sender,
                               args.subject)
    print(f'Emails found: {email_count}')
