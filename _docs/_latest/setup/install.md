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

Users can install Forseti using Terraform by clicking the button below.

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://console.cloud.google.com/cloudshell/open?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2Fforseti-security%2Fterraform-google-forseti.git&cloudshell_git_branch=master&cloudshell_working_dir=examples/install_simple&cloudshell_image=gcr.io%2Fgraphite-cloud-shell-images%2Fterraform%3Alatest&cloudshell_tutorial=.%2Ftutorial.md)

Documentation on installing can be found [here](https://registry.terraform.io/modules/terraform-google-modules/forseti/google).

## What's next

* Learn how to customize
  [Inventory]({% link _docs/latest/configure/inventory/index.md %}) and
  [Scanner]({% link _docs/latest/configure/scanner/index.md %}).
* Configure Forseti Notifier to send
  [email notifications]({% link _docs/latest/configure/notifier/index.md %}#email-notifications).
* Enable
  [G Suite data collection]({% link _docs/latest/configure/inventory/gsuite.md %})
  for processing by Forseti.
* Learn how to [configure Forseti to run from non-organization
  root]({% link _docs/latest/configure/general/non-org-root.md %}).
  
