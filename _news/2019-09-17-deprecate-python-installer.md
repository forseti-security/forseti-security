---
title: Terraform - Official Installation Path of Forseti Security
author: Hannah Shin
---

Forseti Community,

We’ve heard feedback from many of our users around the current Forseti 
installation and upgrade paths, and we are focusing on delivering a 
faster, simpler, and more consistent experience with Terraform.

Starting with Forseti Security v2.22.0 on October 3, 2019, Forseti will support 
Terraform as the official installation path. The Python-based Deployment Manager 
installer will be deprecated and will no longer be available as an 
installation option for future releases. 

We have created a migration script and documentation to help you seamlessly 
migrate from Deployment Manager to Terraform:

* For v2.18.0+ users, refer to the instructions to migrate 
[here](/docs/latest/setup/migrate.html).

* For versions earlier than v2.18.0, please upgrade incrementally to v2.18.0 through 
Deployment Manager following the steps [here](/docs/latest/setup/upgrade.html) 
first before migrating.

You can learn more about the Forseti Terraform module source code 
[here](https://registry.terraform.io/modules/terraform-google-modules/forseti/google/).

Please reach out to us on [Slack](https://forsetisecurity.slack.com/) or discuss@forsetisecurity.org with any questions.
