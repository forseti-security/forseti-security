#!/usr/bin/env python

import os
import sys
import argparse
import json
import time
import requests

SLACK_API_TOKEN = os.environ["SLACK_API_TOKEN"]


def verify_slack_message(channel, msg_text, after_ts=None, retries=1):
    PARAMS = {
        'token': SLACK_API_TOKEN,
        'channel': channel
    }

    while retries != 0:
        response = requests.get("https://slack.com/api/channels.history", params=PARAMS)
        response_obj = json.loads(response.text)
        if not response_obj["ok"]:
            print(response_obj)
            sys.exit(1)

        messages = response_obj["messages"]
        for i in messages:

            if i["text"].strip() == msg_text.strip():
                if after_ts and after_ts < i["ts"]:
                    return True
                else:
                    return True
        retries -= 1
        if retries != 0:
            time.sleep(5)

    return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Confirms that a slack message exist')
    parser.add_argument('--channel', required=True, help='from')
    parser.add_argument('--msg_text', required=True, help='subject')
    parser.add_argument('--after_timestamp', help='after timestamp')
    parser.add_argument('--retries', type=int, default=1,  help='retries')
    args = parser.parse_args()

    print(verify_slack_message(args.channel, args.msg_text, args.after_timestamp, args.retries))
