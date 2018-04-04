---
title: Upgrading from Forseti v1.x
order: 001
---

# {{ page.title }}

This guide explains how to use the Forseti upgrade tool.

## Before you begin

Before you upgrade Forseti, you'll need the following:

  - A G Suite super admin account to complete the [Domain-wide delegation steps]
({% link _docs/latest/configure/gsuite-group-collection.md %}). 
Forseti 2.0 requires G Suite enablement, so you'll need this before you start the installation.
  - The Forseti Security 2.0 installer only migrates configuration and rule files.


### Activate Google Cloud Shell

It's recommended to use [Cloud Shell](https://cloud.google.com/shell/docs/quickstart) to run the
Forseti installer. This ensures you're using the latest version of Cloud SDK since it's included
in Cloud Shell. To prepare to run the Forseti setup wizard, follow the steps below:

  1. Access the [Cloud Platform Console](https://console.cloud.google.com/).
  1. In the **Select a project** drop-down list at the top of the console, select the project where
  you have Forseti v1.x deployed.
  1. On the top right of the console, click **Activate Google Cloud Shell**. The Cloud
  Shell panel opens at the bottom of the page.

### Run setup

  1. After you activate Cloud Shell, download Forseti. The installer is included.
     Getting `master` branch will install [the latest released version of Forseti]({% link releases/index.md %}).

      ```bash
      git clone -b master --single-branch https://github.com/GoogleCloudPlatform/forseti-security.git
      ```

  1. Run the installer.

     ```bash 
     python setup/installer.py
     ```

  1. When prompted to migrate configuration files, select "Y".

  1. The installer will prompt you for the necessary information to install Forseti.

     If you didn't configure the following options in v1.x, you'll be prompted during the upgrade:

     * SendGrid API key \[Optional\]: Used for sending email via SendGrid. For more information, 
       see [Enabling email notifications]({% link _docs/latest/configure/email-notification.md %}).
     * Email recipient \[Optional\]: If a SendGrid API key is provided, you will also be asked
       to whom Forseti should send the email notifications.
     * G Suite super admin email \[Not optional\]: This is part of the
       [G Suite Google Groups collection]({% link _docs/latest/configure/gsuite-group-collection.md %})
       and is required.
       Ask your G Suite admin if you don't know which super admin email to use.
  1. Forseti is now upgraded to v2.x. To manually remove unused resources, follow the instructions
  at the end of the installation process.

## What's next

  - Customize [Inventory]({% link _docs/latest/configure/inventory/index.md %}) and
  [Scanner]({% link _docs/latest/configure/scanner/index.md %}).
  - Configure Forseti to send [email notifications]({% link _docs/latest/configure/email-notification.md %}).
  - Enable [G Suite Google Groups collection]({% link _docs/latest/configure/gsuite-group-collection.md %})
  for processing by Forseti.
