---
title: Installation
order: 002
---
# {{ page.title }}

This quickstart explains how to use the Forseti setup wizard to get started
quickly with Forseti Security for Google Cloud Platform (GCP) projects.

## Before you begin

To complete this quickstart, you will need:

  - A GCP organization for which you want to deploy Forseti.
  - Org Admin IAM role in order for the script to assign the Forseti 
  service account roles on the organization IAM policy.

## Setting up Forseti Security

The setup wizard presents a series of prompts to guide you through setting
up a Forseti deployment, then generates a deployment template and configuration
file based on your input.

  1. First, download Forseti. The setup wizard is included:
  
      ```bash
      git clone https://github.com/GoogleCloudPlatform/forseti-security
      ```
      
      If you want to deploy a particular release:
      
      ```
      git checkout <release version>
      ```

  1. Navigate to the setup wizard directory:
  
      ```bash
      cd forseti-security/scripts/gcp_setup
      ```

  1. Start the setup process:
     
      ```bash
      python setup_forseti.py
      ```

  1. If you set up a service account to retrieve GSuite groups, follow the
  post-setup instructions to enable your GSuite service account for domain-wide delegation.

Forseti Security is now set up for your project and you can enable modules
to use for your resources.

## What's next

  - Set up [Inventory]({% link _docs/quickstarts/inventory/index.md %}),
  [Scanner]({% link _docs/quickstarts/scanner/index.md %}),
  and [Enforcer]({% link _docs/quickstarts/enforcer/index.md %}).
  - Set up Forseti to send [email notifications]({% link _docs/howto/configure/email-notification.md %}).
  - Enable [GSuite Google Groups collection]({% link _docs/howto/configure/gsuite-group-collection.md %})
  for processing by Forseti.
  - Learn how to [change a deployment]({% link _docs/howto/deploy/change-gcp-deployment.md %}).

