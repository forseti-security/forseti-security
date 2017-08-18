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

We recommend using Cloud Shell to run Forseti setup wizard to ensure 
that you have the latest version of gcloud and the necessary gcloud components.
Also, using Cloud Shell pre-authenticates you in your gcloud environment, 
which is a necessary step for using the setup wizard.

### Preliminary steps for setup without Cloud Shell

If you choose not to use Cloud Shell, then make sure to do the following:

  1. Install [gcloud](https://cloud.google.com/sdk/downloads). If you already have 
     gcloud, then update it.
     
  1. Ensure you have gcloud alpha components installed.
  
  1. Authenticate your user.
     
  1. Set your project.

### Using Cloud Shell

Open a Cloud Shell session in your Google Cloud console.

### Running setup

  1. Download Forseti. The setup wizard is included:
  
      ```bash
      git clone https://github.com/GoogleCloudPlatform/forseti-security
      ```
      
      If you want to install from a particular release:
      
      ```
      git checkout <release version>
      ```

  1. Navigate to the setup wizard directory:
  
      ```bash
      cd forseti-security/scripts/gcp_setup
      ```

  1. Invoke the setup:
  
      If you downloaded a certain release of Forseti, specify the release version
      to the setup wizard.
     
      ```bash
      # Default: master branch
      python setup_forseti.py
      
      # Specify a branch (e.g. develop)
      python setup_forseti.py --branch develop
      
      # Display help information
      python setup_forseti.py -h
      ```

  1. Setup will infer the necessary information to install Forseti. You will be 
     prompted to enter a SendGrid API key, which is optional. (More information 
     on setting up  [email notifications]({% link _docs/howto/configure/email-notification.md %}))

  1. After successfully running the setup and Deployment Manager, you should 
     follow instructions for enabling [GSuite Google Groups collection]({% link _docs/howto/configure/gsuite-group-collection.md %}).

## What's next

  - Set up [Inventory]({% link _docs/quickstarts/inventory/index.md %}),
  [Scanner]({% link _docs/quickstarts/scanner/index.md %}),
  and [Enforcer]({% link _docs/quickstarts/enforcer/index.md %}).
  - Set up Forseti to send [email notifications]({% link _docs/howto/configure/email-notification.md %}).
  - Enable [GSuite Google Groups collection]({% link _docs/howto/configure/gsuite-group-collection.md %})
  for processing by Forseti.
  - Learn how to [change a deployment]({% link _docs/howto/deploy/change-gcp-deployment.md %}).
