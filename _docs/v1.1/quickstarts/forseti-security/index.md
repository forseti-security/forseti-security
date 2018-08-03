---
title: Installation
order: 002
---
# {{ page.title }}

This quickstart explains how to use the Forseti setup wizard, which helps to
automate some of the Forseti installation and setup on GCP.

**If you are trying to install Forseti in a developer environment, please
refer to the [Development Environment Setup]({% link _docs/v1.1/howto/deploy/dev-setup.md %}).**

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

It's recommended to use [Cloud Shell](https://cloud.google.com/shell/docs/quickstart) to run the Forseti setup wizard. This ensures you're using the latest version of Cloud SDK since it's included in Cloud Shell.

### Run setup

  1. [Open Google Cloud Shell and download Forseti code](https://console.cloud.google.com/cloudshell/open?git_repo=https%3A%2F%2Fgithub.com%2FGoogleCloudPlatform%2Fforseti-security&page=editor)
     using Cloud Shell's one-step installation process.

     To get a particular release, e.g. 1.1.7, use the following command (note the "v"):

      ```bash
      git checkout tags/v1.1.7
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

  1. Setup will infer the necessary information to install Forseti.

     If you ran the `setup_forseti.py` without extra flags, you will be
     prompted to enter the following:

     * SendGrid API key: Optional, used for sending email via SendGrid. Refer to
       setting up [email notifications]({% link _docs/v1.1/howto/configure/email-notification.md %})).
     * Email recipient: If a SendGrid API key is provided, you will also be asked
       to whom Forseti should send the email notifications.
     * G Suite super admin email: This is part of the
       [G Suite Google Groups collection]({% link _docs/v1.1/howto/configure/gsuite-group-collection.md %})
       and is necessary for running [IAM Explain]({% link _docs/v1.1/quickstarts/explain/index.md %}).
       Ask your G Suite Admin if you don't know what the super admin email is.

  1. If you previously used Cloud Shell to SSH to a Compute Engine instance and
     you set an SSH passphrase, setup prompts you to enter the passphrase.
     The Forseti setup uses secure copy (SCP) to copy the auto-generated G Suite
     service account key as well as the Forseti configuration files to the
     Forseti Compute Engine instance .

  1. After the setup wizard successfully completes Forseti setup and deployment,
     complete the steps to [enable G Suite Google Groups collection]({% link _docs/v1.1/howto/configure/gsuite-group-collection.md %}). This is a **required** step if you also plan to deploy IAM Explain.

## What's next

  - Customize [Inventory]({% link _docs/v1.1/quickstarts/inventory/index.md %}),
  [Scanner]({% link _docs/v1.1/quickstarts/scanner/index.md %}),
  and [Enforcer]({% link _docs/v1.1/quickstarts/enforcer/index.md %}).
  - Configure Forseti to send [email notifications]({% link _docs/v1.1/howto/configure/email-notification.md %}).
  - Enable [G Suite Google Groups collection]({% link _docs/v1.1/howto/configure/gsuite-group-collection.md %})
  for processing by Forseti.
  - Learn how to [change a deployment]({% link _docs/v1.1/howto/deploy/change-gcp-deployment.md %}).
