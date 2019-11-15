# verify_slack_message

## Prerequisite

- Create Slack app

  - Go to => https://api.slack.com/apps?new_app=1
  
- Add OAuth Scopes

  - Go to => https://api.slack.com/apps/<SLACK_APP_ID>/oauth?
  
  - Scroll down to the Scopes panel.
  
  - Click Button => "Add an OAuth Scope"
  
  - Select in combobox => channels:history
  
- Install App to Workspace

  - Go to => https://api.slack.com/apps/<SLACK_APP_ID>/oauth?
  
  - Click Button => "Install App to Workspace"
  
  - Click Button => "Allow"
  
- Copy OAuth Access Token

  - Goto => https://api.slack.com/apps/<SLACK_APP_ID>/oauth?
  xoxp-RANDOM-RANDOM-RANDOM-RANDOM
    
- Copy Slack channel_id

  Sign into slack's web interface.
  
  https://app.slack.com/client/<REDACTED>/<CHANNEL_ID>/user_profile/<REDACTED>
  
- Test the endpoint

  https://api.slack.com/methods/channels.history/test
  
  - Input the token
  - Input channel
  - Click Button => "Test Method"
  

## Python packages

    cd /path/to/verify_slack_message pip install -r requirements.txt
    
## Run

    cd /path/to/verify_slack_message
    verify_slack_message.py --channel SLACK_CHANNEL_ID --msg_text "hello world!" --after_timestamp 1573855484 --retries 5