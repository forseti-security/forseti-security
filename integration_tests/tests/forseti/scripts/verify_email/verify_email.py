#!/usr/bin/env python

from __future__ import print_function
import pickle
import os.path
import argparse
import time

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# If modifying these scopes, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def get_service():
    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)
    return service


def verify_email(sender=None, subject=None, after_timestamp=None, before_timestamp=None, filename=None, importance=None, retries=3):
    """
    verify at least one mail fitting query exist.
    """

    service = get_service()

    query = []

    if sender:
        query.append("from:(" + sender + ")")

    if subject:
        query.append("subject:(" + subject + ")")

    if after_timestamp:
        query.append("after:" + after_timestamp)

    if before_timestamp:
        query.append("before:" + before_timestamp)

    if filename:
        query.append("filename:" + filename)

    if importance:
        query.append("is:" + importance)

    # Call the Gmail API
    response = service.users().messages().list(userId='me', q=" ".join(query)).execute()

    if retries != 0:
        while retries != 0:
            response = service.users().messages().list(userId='me', q=" ".join(query)).execute()
            if 'messages' in response:
                return True
            retries -= 1
            time.sleep(5)

    return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Confirms that a gmail email exist')
    parser.add_argument('--from_sender', help='from')
    parser.add_argument('--subject', help='subject')
    parser.add_argument('--after_timestamp', help='after timestamp')
    parser.add_argument('--before_timestamp', help='before timestamp')
    parser.add_argument('--filename', help='attached filename')
    parser.add_argument('--importance', help='importance: starred, unstarred, snoozed, read, unread')
    parser.add_argument('--retries', type=int, default=1,  help='retries')
    args = parser.parse_args()
    print(verify_email(args.from_sender, args.subject, args.after_timestamp, args.before_timestamp, args.filename, args.importance, args.retries))
