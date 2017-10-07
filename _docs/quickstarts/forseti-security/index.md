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

### Activate Google Cloud Shell

It's recommended to use [Cloud Shell](https://cloud.google.com/shell/docs/quickstart) to run the Forseti setup wizard. This ensures you're using the latest version of Cloud SDK since it's included in Cloud Shell. To prepare to run the Forseti setup wizard, follow the steps below:

  1. Access the [Cloud Platform Console](https://console.cloud.google.com/).
  1. In the **Select a project** drop-down list at the top of the console, select the project where you want to deploy Forseti.
  1. On the top right of the console, click the icon to **Activate Google Cloud Shell**. The Cloud Shell panel opens at the bottom of the page.

### Run setup
  
  1. Once you've started Cloud Shell, download Forseti. The setup wizard is included:
  
      ```bash
      git clone -b master --single-branch https://github.com/GoogleCloudPlatform/forseti-security

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
     
  1. If you previously used Cloud Shell to SSH to a Compute Engine instance and 
     you set an SSH passphrase, setup prompts you to enter the passphrase. 
     The Forseti setup uses secure copy (SCP) to copy the auto-generated G Suite 
     service account key to the Forseti Compute Engine instance.

  1. After the setup wizard successfully completes Forseti setup and deployment, 
     complete the steps to [enable G Suite Google Groups collection]({% link _docs/howto/configure/gsuite-group-collection.md %}). This is a **required** step if you also plan to deploy IAM Explain.

## What's next

  - Configure [Inventory]({% link _docs/quickstarts/inventory/index.md %}),
  [Scanner]({% link _docs/quickstarts/scanner/index.md %}),
  and [Enforcer]({% link _docs/quickstarts/enforcer/index.md %}).
  - Configure Forseti to send [email notifications]({% link _docs/howto/configure/email-notification.md %}).
  - Enable [G Suite Google Groups collection]({% link _docs/howto/configure/gsuite-group-collection.md %})
  for processing by Forseti.
  - Learn how to [change a deployment]({% link _docs/howto/deploy/change-gcp-deployment.md %}).
