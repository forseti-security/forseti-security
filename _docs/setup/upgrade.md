---
title: Upgrading from Forseti v1.x
order: 001
---

# {{ page.title }}

This guide explains how to use the Forseti upgrade tool.

## Before you begin

Prior to upgrading the setup wizard, you will need to know:

  - Forseti Security 2.0 requires G Suite enablement. 
  You must be able to specify a G Suite Super Admin account 
  and perform the [Domain-wide Delegation steps]({% link _docs/configure/gsuite-group-collection.md %}).
  Have this information and be prepared to do this 
  prior to starting the installation.
  - The Forseti Security 2.0 installer only migrates configuration and rule files.
  - Installing Forseti 2.0 will not remove any existing data from the 1.x version, however, at the end of the
  installation, you will be able to identify the list of v1.x related resources which you can remove manually.


### Activate Google Cloud Shell

It's recommended to use [Cloud Shell](https://cloud.google.com/shell/docs/quickstart) to run the
Forseti installer. This ensures you're using the latest version of Cloud SDK since it's included
in Cloud Shell. To prepare to run the Forseti setup wizard, follow the steps below:

  1. Access the [Cloud Platform Console](https://console.cloud.google.com/).
  1. In the **Select a project** drop-down list at the top of the console, select the project where
  you have your Forseti v1.x deployed.
  1. On the top right of the console, click the icon to **Activate Google Cloud Shell**. The Cloud
  Shell panel opens at the bottom of the page.

### Run setup

  1. Once you've started Cloud Shell, download Forseti. The installer is included.
     Getting `master` branch will install Forseti v2.0.

      ```bash
      git clone -b master --single-branch https://github.com/GoogleCloudPlatform/forseti-security.git
      ```

  1. Run the installer.

     ```bash 
     python setup/installer.py
     ```

  1. When prompted to migrate configuration files choose “Y”.

  1. Installer will prompt the necessary information to install Forseti.

     If you don't have this information configured in v1.x, you will be prompted for them again during the installation:

     * SendGrid API key (optional): Used for sending email via SendGrid. Refer to
       setting up [email notifications]({% link _docs/configure/email-notification.md %})).
     * Email recipient (optional): If a SendGrid API key is provided, you will also be asked
       to whom Forseti should send the email notifications.
     * G Suite super admin email (required): This is part of the
       [G Suite Google Groups collection]({% link _docs/configure/gsuite-group-collection.md %})
       and is necessary.
       Ask your G Suite Admin if you don't know which super admin email to use.


## What's next

  - Customize [Inventory]({% link _docs/configure/inventory/index.md %}),
  [Scanner]({% link _docs/configure/scanner/index.md %}),
  and [Enforcer]({% link _docs/configure/enforcer/index.md %}).
  - Configure Forseti to send [email notifications]({% link _docs/configure/email-notification.md %}).
  - Enable [G Suite Google Groups collection]({% link _docs/configure/gsuite-group-collection.md %})
  for processing by Forseti.
