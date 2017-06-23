---
title: Forseti Security Quickstart
order: 002
---
# Forseti Security Quickstart

This quickstart explains how to use the Forseti setup wizard to get started
quickly with Forseti Security for Google Cloud Platform (GCP) projects.

## Before you begin

To complete this quickstart, you will need:

  - A GCP organization for which you want to deploy Forseti.

## Setting up Forseti Security

The setup wizard saves the information you input to create a new Forseti
deployment on GCP. Follow the setup prompts below to save your Forseti
configuration:

  1. To download the setup wizard, run:

         git clone https://github.com/GoogleCloudPlatform/forseti-security

  1. Navigate to the setup wizard directory:

         cd forseti-security/scripts/gcp_setup

  1. Start the setup process:

         python setup_forseti.py

  1. Follow the prompts to download and install the
  [gcloud command-line tool](https://cloud.google.com/sdk/gcloud/).
  1. Follow the prompts to authenticate your GCP account in a web browser,
  then return to the command-line.
  1. Enter the organization for which you want to deploy Forseti.
  1. Create a new project or enter an existing project ID you want to use for
  Forseti Security. Note that it's best to use a project dedicated to running
  Forseti.
  1. The setup wizard checks for valid configurations or creates a new one,
  then it checks if billing is enabled for your project.
    2. If billing isn't enabled, follow the prompts to enable billing, then
    return to the command-line.
  1. Next, the setup wizard automaticlaly enables required APIs:
    - Cloud SQL API
    - Cloud SQL Admin API
    - Cloud Resource Manager API
    - Admin SDK API
    - Deployment Manager API
  1. Create a new service account or enter an existing service account for
  accessing GCP.
  1. Optionally create a new service account or enter an existing service
  account for getting GSuite groups.
  1. Next, the setup wizard automatically assigns roles to the GCP service
  account:
  
    - `roles/browser`
    - `roles/compute.networkAdmin`
    - `roles/editor`
    - `roles/iam.securityReviewer`
    - `roles/resourcemanager.folderAdmin`
    - `roles/storage.admin`
    
  1. Enter a name for your bucket and Cloud SQL instance.
  1. Optionally create data storage and a Cloud SQL instance.
  1. If you set up a service account to retrieve GSuite groups, follow the
  post-setup instructions to access your project in the Cloud Platform Console
  and **Enable domain-wide-delegation**.

Forseti Security is now set up for your project and you can enable modules
to use for your resources.

## What's next

  - Set up [Inventory](inventory-quickstart), [Scanner](scanner-quickstart),
  and [Enforcer](enforcer-quickstart).
  - Set up Forseti to send [email notifications](email-notification-howto).
  - Enable [GSuite Google Groups collection](gsuite-group-collection-howto) for
  processing by Forseti.
  - Learn how to [change a deployment](change-deployment-howto).

