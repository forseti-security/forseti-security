---
title: Installation
order: 002
---
# {{ page.title }}

This quickstart explains how to use the Forseti setup wizard, which helps to 
automate some of the Forseti installation and setup process.

Setup wizard is not available prior to version 1.1.0.

## Before you begin

Prior to running the setup wizard, you will need:

  - A GCP organization for which you want to deploy Forseti.
  - Org Admin IAM role in order for the script to assign the Forseti 
  service account roles on the organization IAM policy.
  - A GCP project dedicated to Forseti.
  - Enable billing on the project.


## Setting up Forseti Security

The setup wizard automatically determines setup information, generates a 
deployment template, and creates a Forseti deployment.

## Activate Google Cloud Shell

We recommend using [Cloud Shell](https://cloud.google.com/shell/docs/quickstart)
to run Forseti setup wizard to ensure that you have the latest version of Cloud SDK.

### Running setup
  
  1. Once you've started Cloud Shell, download Forseti. The setup wizard is included:
  
      ```bash
      git clone https://github.com/GoogleCloudPlatform/forseti-security
      ```
      
      To install the latest release:
      
      ```
      git checkout master
      ```

  1. Navigate to the setup wizard directory:
  
      ```bash
      cd forseti-security/scripts/gcp_setup
      ```

  1. Invoke the setup:
     
      ```bash
      python setup_forseti.py
      ```
      
      To see additional configurations for the setup:

      ```bash
      python setup_forseti.py -h
      ```

  1. Setup will infer the necessary information to install Forseti. You will be 
     prompted to enter a SendGrid API key, which is optional. (More information 
     on setting up  [email notifications]({% link _docs/howto/configure/email-notification.md %}))
     
  1. You may be prompted to enter an ssh passphrase for Compute Engine. This will only 
     happen if you've previously used Cloud Shell to ssh to a Compute Engine instance and
     set a passphrase for ssh. The Forseti setup uses scp to copy the auto-generated G Suite 
     service account key to the Forseti GCE instance.

  1. After successfully running the setup and Deployment Manager, you should 
     follow instructions for enabling [G Suite Google Groups collection]({% link _docs/howto/configure/gsuite-group-collection.md %}).


## What's next

  - Set up [Inventory]({% link _docs/quickstarts/inventory/index.md %}),
  [Scanner]({% link _docs/quickstarts/scanner/index.md %}),
  and [Enforcer]({% link _docs/quickstarts/enforcer/index.md %}).
  - Set up Forseti to send [email notifications]({% link _docs/howto/configure/email-notification.md %}).
  - Enable [GSuite Google Groups collection]({% link _docs/howto/configure/gsuite-group-collection.md %})
  for processing by Forseti.
  - Learn how to [change a deployment]({% link _docs/howto/deploy/change-gcp-deployment.md %}).
