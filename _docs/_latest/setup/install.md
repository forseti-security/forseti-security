---
title: Install
order: 001
---

# {{ page.title }}

This guide explains how to use the Forseti installation tool.

---

## Before you begin

Before you run the setup wizard, you will need:

* A Google Cloud Platform (GCP) organization you want to deploy
  Forseti for.
* An Organization Administrator Cloud Identity and Access Management (Cloud IAM)
  role so the script can assign the Forseti service account roles on the
organization Cloud IAM policy.
* A GCP project dedicated to Forseti. You can reuse the same project that has
  Forseti 1.0 installed in it.
* Enable billing on the project.


## Setting up Forseti Security

The installer automatically determines setup information, generates a deployment
template, and creates a Forseti deployment.

### Activate Google Cloud Shell

It's best to use
[Cloud Shell](https://cloud.google.com/shell/docs/quickstart) to run the Forseti
installer. This ensures you're using the latest version of Cloud SDK since it's
included in Cloud Shell.

### Run setup

  1. [Open Google Cloud Shell and download Forseti code](https://console.cloud.google.com/cloudshell/open?git_repo=https%3A%2F%2Fgithub.com%2FGoogleCloudPlatform%2Fforseti-security&page=editor)
     using Cloud Shell's one-step installation process.
     The installer is included in the `install/` directory.

  1. Check out the specific version of Forseti you want to install by using a tag like `v2.0.0.`:

      ```bash
      # Make sure you are in the forseti-security folder.
      # If the tag exists in the remote repository but you are unable to checkout the tag,
      # run command `git fetch --all` to fetch all the latest branch/tag information.
      git checkout tags/v2.0.0
      ```

  1. Install both client and server by running the installer:

     ```bash
     python install/gcp_installer.py
     ```

     If you don't plan to share your Forseti instance with other non-administrators, 
     you can choose to install the server instance only and access Forseti from there.
     ```bash
     python install/gcp_installer.py --type=server
     ```

     To see additional configurations for the setup, run the following:

     ```bash
     python install/gcp_installer.py -h
     ```

  1. The installer will infer the necessary information to install Forseti.

     If you ran the `install/gcp_installer.py` without extra flags, you will be
     prompted to enter the following:

     * SendGrid API key \[Optional\]: Used for sending email via SendGrid. For
       more information, see how to
       [enable email notifications]({% link _docs/latest/configure/notifier/index.md %}#email-notifications-with-sendgrid).
     * Email recipient \[Optional\]: If you provide a SendGrid API key, you will
       also be asked to whom Forseti should send the email notifications.
     * G Suite super admin email \[Not optional\]: This is part of the
       [G Suite data collection]({% link _docs/latest/configure/inventory/gsuite.md %})
       and is necessary. Ask your G Suite Admin if you don't know the super
       admin email.

  1. After you install the server, a cron job automatically runs every other hour
     to get the latest configuration file and execute the following commands on
     your Cloud Storage bucket:

     ```bash
       MODEL_ID=$(/bin/date -u +%Y%m%dT%H%M%S)
       forseti inventory create --import_as ${MODEL_ID}
       forseti model use ${MODEL_ID}
       forseti scanner run
       forseti notifier run
     ```

## What's next

* Learn how to customize
  [Inventory]({% link _docs/latest/configure/inventory/index.md %}) and
  [Scanner]({% link _docs/latest/configure/scanner/index.md %}).
* Configure Forseti Notifier to send
  [email notifications]({% link _docs/latest/configure/notifier/index.md %}#email-notifications-with-sendgrid).
* Enable
  [G Suite data collection]({% link _docs/latest/configure/inventory/gsuite.md %})
  for processing by Forseti.
