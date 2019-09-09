---
title: Install with Python Installer
order: 002
---

# {{ page.title }}

This guide explains how to use the python-based Forseti installation tool.

---

## Before you begin

<span style="color:red">
This python-based installer will be deprecated on September 30, 2019.

It is highly recommended that you try the easier to use terraform-based
installer, which will become the only installer available after
September 30, 2019.
</span>

### Activate Google Cloud Shell

It's best to use
[Cloud Shell](https://cloud.google.com/shell/docs/quickstart) to run the Forseti
installer. This ensures you're using the latest version of Cloud SDK since it's
included in Cloud Shell. To prepare to run the Forseti setup wizard, follow the
steps below:

  1. Go to the [GCP Console](https://console.cloud.google.com/).
  1. In the **Select a project** drop-down list at the top of the console,
     select the project you want to deploy Forseti to.
  1. On the top right, click the icon to **Activate Google Cloud Shell**. The
     Cloud Shell panel opens at the bottom of the page.

### Run setup

  1. After you've started Cloud Shell, download Forseti. The installer is
  included in the `install/` directory:

      ```bash
      git clone https://github.com/forseti-security/forseti-security.git
      ```

  1. Check out the specific version of Forseti you want to install by using a tag like `v2.19.0.`:
      ```bash
      # Make sure you are in the forseti-security folder.
      cd forseti-security

      # If the tag exists in the remote repository but you are unable to checkout the tag,
      # run command `git fetch --all` to fetch all the latest branch/tag information and run
      # the checkout command again.
      git checkout tags/v2.19.0
      
      # Install `future` package if it doesn't already exist.
      pip3 install future
      ```

  1. Install both client and server by running the installer:

     ```bash
     python3 install/gcp_installer.py
     ```

     If you don't plan to share your Forseti instance with other non-administrators, 
     you can choose to install the server instance only and access Forseti from there.
     ```bash
     python3 install/gcp_installer.py --type=server
     ```

     Installing Forseti on multiple roots by specifying the roots using `--composite-root-resources` flag. 
     ```bash
     # Example command to have forseti running on project a and folder b.
     python3 install/gcp_installer.py --composite-root-resources "projects/a,folders/b"
     ```
     You can read more about the composite root resources [here]({% link _docs/v2.19/configure/general/non-org-root.md %}).

     To see additional configurations for the setup, run the following:

     ```bash
     python3 install/gcp_installer.py -h
     ```
     Install Forseti in shared VPC by running the installer with additional flags.
     
     ```
     python3 install/gcp_installer.py --vpc-host-project-id={VPC_HOST_PROJECT_ID} --vpc-host-network={VPC_HOST_NETWORK} --vpc-host-subnetwork={VPC_HOST_SUBNETWORK}
     ```

  1. The installer will infer the necessary information to install Forseti.

     If you ran the `install/gcp_installer.py` without extra flags, you will be
     prompted to enter the following:

     * SendGrid API key \[Optional\]: Used for sending email via SendGrid. For
       more information, see how to
       [enable email notifications]({% link _docs/v2.19/configure/notifier/index.md %}#email-notifications).
     * Email recipient \[Optional\]: If you provide a SendGrid API key, you will
       also be asked to whom Forseti should send the email notifications.
     * G Suite super admin email \[Optional\]: This is part of the
       [G Suite data collection]({% link _docs/v2.19/configure/inventory/gsuite.md %}).
       Ask your G Suite Admin if you don't know the super admin email.

       The following functionalities will not work without G Suite integration:
        * G Suite groups and users in Inventory
        * Group Scanner
        * Group expansion in Explain
        
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
  [Inventory]({% link _docs/v2.19/configure/inventory/index.md %}) and
  [Scanner]({% link _docs/v2.19/configure/scanner/index.md %}).
* Configure Forseti Notifier to send
  [email notifications]({% link _docs/v2.19/configure/notifier/index.md %}#email-notifications).
* Enable
  [G Suite data collection]({% link _docs/v2.19/configure/inventory/gsuite.md %})
  for processing by Forseti.
* Learn how to [configure Forseti to run from non-organization
  root]({% link _docs/v2.19/configure/general/non-org-root.md %}).
  
