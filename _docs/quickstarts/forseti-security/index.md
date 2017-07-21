---
title: Forseti Security
order: 002
---
# {{ page.title }}

This quickstart explains how to use the Forseti setup wizard to get started
quickly with Forseti Security for Google Cloud Platform (GCP) projects.

## Before you begin

To complete this quickstart, you will need:

  - A GCP organization for which you want to deploy Forseti.
  - Org Admin IAM role in order for the script to assign the Forseti 
  service account roles on the _organization_.

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
  
      If you downloaded a certain release of Forseti, specify the release version
      to the setup wizard.

      Setup wizard is not available prior to 1.1.0.
      
      _e.g. Deploy 1.1.0:_
      
      ```bash
      python setup_forseti.py --version 1.1.0
      ```
  
     _Default: runs master branch_
     
      ```bash
      python setup_forseti.py
      ```
      
      _Run a certain branch:_
      
      ```bash
      python setup_forseti.py --branch develop
      ```

  1. Follow the prompts to download and install the
  [gcloud command-line tool](https://cloud.google.com/sdk/gcloud/).
  1. Follow the prompts to authenticate your GCP account in a web browser,
  then return to the command-line.
  1. Enter the organization for which you want to deploy Forseti, if prompted.
  1. Create a new project or enter an existing project ID you want to use for
  Forseti Security. Note that it's best to use a project dedicated to running
  Forseti.
  1. The setup wizard checks for valid configurations or creates a new one,
  then it checks if billing is enabled for your project.
      * If billing isn't enabled, follow the prompts to enable billing, then
    return to the command-line.
  1. Next, the setup wizard automatically enables required APIs:
  
  {% include _global/required-apis.md %}
  
  1. Create a new service account or enter an existing service account for
  accessing GCP.
  1. Optionally create a new service account or enter an existing service
  account for getting GSuite groups.
  1. Next, the setup wizard automatically assigns the required roles to the GCP service
  account. The [Forseti Security Best Practices Guide]({% link _docs/guides/forseti-security-best-practices.md %})
  has more detail on the required roles.
  1. Enter a name for your bucket and Cloud SQL instance.
  1. Setup wizard will create a Deployment Manager template based on your input
  as well as ask whether you want to create the deployment.
  1. Optionally create the bucket and a Cloud SQL instance. Only do this if you 
  do not plan to create a deployment via Deployment Manager.
  1. If you set up a service account to retrieve GSuite groups, follow the
  post-setup instructions to enable your GSuite service account for domain-wide delegation.

Forseti Security is now set up for your project and you can enable modules
to use for your resources.

## What's next

  - Set up [Inventory]({% link _docs/quickstarts/inventory/index.md %}),
  [Scanner]({% link _docs/quickstarts/scanner/index.md %}),
  and [Enforcer]({% link _docs/quickstarts/enforcer/index.md %}).
  - Set up Forseti to send [email notifications]({% link _docs/howto/email-notification.md %}).
  - Enable [GSuite Google Groups collection]({% link _docs/howto/gsuite-group-collection.md %})
  for processing by Forseti.
  - Learn how to [change a deployment]({% link _docs/howto/change-gcp-deployment.md %}).

