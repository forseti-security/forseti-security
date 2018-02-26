---
title: Forseti Installation
order: 001
---

# {{ page.title }}

This guide explains how to use the Forseti installation tool.

## Before you begin

Prior to running the setup wizard, you will need:

  - A GCP organization for which you want to deploy Forseti.
  - Org Admin IAM role in order for the script to assign the Forseti
  service account roles on the organization IAM policy.
  - A GCP project dedicated to Forseti, you can reuse the same 
  project that has Forseti 1.0 installed in it.
  - Enable billing on the project.


## Setting up Forseti Security

The installer automatically determines setup information, generates a
deployment template, and creates a Forseti deployment.

### Activate Google Cloud Shell

It's recommended to use [Cloud Shell](https://cloud.google.com/shell/docs/quickstart) to run the
Forseti installer. This ensures you're using the latest version of Cloud SDK since it's included
in Cloud Shell. To prepare to run the Forseti setup wizard, follow the steps below:

  1. Access the [Cloud Platform Console](https://console.cloud.google.com/).
  1. In the **Select a project** drop-down list at the top of the console, select the project where
  you want to deploy Forseti.
  1. On the top right of the console, click the icon to **Activate Google Cloud Shell**. The Cloud
  Shell panel opens at the bottom of the page.

### Run setup

  1. Once you've started Cloud Shell, download Forseti. The installer is included.
     Getting `2.0-dev-rc1` branch will install Forseti v2.0 Release Candidate 1.

      ```bash
      git clone -b master --single-branch https://github.com/GoogleCloudPlatform/forseti-security.git
      ```


  1. Running the installer:

     To install both client and server:
     ```bash 
     python setup/installer.py
     ```

      To see additional configurations for the setup:

      ```bash
      python installer.py -h
      ```

  1. Installer will infer the necessary information to install Forseti.

     If you ran the `installer.py` without extra flags, you will be
     prompted to enter the following:

     * SendGrid API key \[Optional\]: Used for sending email via SendGrid. Refer to
       setting up [email notifications]({% link _docs/configure/email-notification.md %})).
     * Email recipient \[Optional\]: If a SendGrid API key is provided, you will also be asked
       to whom Forseti should send the email notifications.
     * G Suite super admin email \[Not optional\]: This is part of the
       [G Suite Google Groups collection]({% link _docs/configure/gsuite-group-collection.md %})
       and is necessary.
       Ask your G Suite Admin if you don't know what the super admin email is.

  1. By installing the server, There is a cron job scheduled on the server to run every other
   hour that executes the following commands after pulling down the latest configuration file 
   on the GCS bucket.:
     ```bash
       MODEL_ID=$(/bin/date -u +%Y%m%dT%H%M%S)
       forseti inventory create --import_as ${MODEL_ID}
       forseti model use ${MODEL_ID}
       forseti scanner run
       forseti notifier run
     ```


## What's next

  - Customize [Inventory]({% link _docs/configure/inventory/index.md %}),
  [Scanner]({% link _docs/configure/scanner/index.md %}).
  - Configure Forseti to send [email notifications]({% link _docs/configure/email-notification.md %}).
  - Enable [G Suite Google Groups collection]({% link _docs/configure/gsuite-group-collection.md %})
  for processing by Forseti.
