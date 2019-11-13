from __future__ import print_function
import pickle
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

import json

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

def verify_email(query, sender, subject, body):
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """

    service = get_service()

    # Call the Gmail API
    response = service.users().messages().list(userId='me', q=query).execute()

    # Get al message ids
    messages = []
    if 'messages' in response:
        messages.extend(response['messages']['id'])

    # print(messages)
    message = service.users().messages().get(userId='me', id=messages[0]["id"]).execute()

    print(json.dumps(message, sort_keys=True, indent = 4, separators = (',', ': ')))
    # labels = results.get('messages', [])
    #
    # if not labels:
    #     print('No labels found.')
    # else:
    #     print('Labels:')
    #     for label in labels:
    #         print(label['name'])

if __name__ == '__main__':
    verify_email("Github", "adf", "Qwe", "adsf")