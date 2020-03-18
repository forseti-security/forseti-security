---
title: Running Forseti from Non-Organization Root
order: 100
---

# {{ page.title }}

By default, Forseti is designed to be installed with complete
organization access, and run with the organization as the root node in the
resource hierarchy.

But, you also have the option to run Forseti on a subset of resources:
1. if you are Org Admin, and you want to run Forseti on a specific folder
1. if you are Folder Admin, and you want to run Forseti on a specific folder
1. if you are Project Admin, and you want to run Forseti on projects that are 
only owned by you.

Inventory, Data Model, and Scanner will be supported for use on these subset
of resources, but Explain will not be supported.

## How to Install

Run the Forseti [Installer]({% link _docs/latest/setup/install.md %}).

By default, the installer will try to assign org-level roles. If you are not
an Org Admin, there will be errors, but you can safely disregard, as you will
manually assign the correct roles later.

## Configure Forseti to Run on a Folder

1. Edit `main.tf` and set `composite_root_resources` variable to point to the 
target folder: `["folders/<foo_folder_id>"]`.

1. You can use the `composite_root_resources` configuration to include 
   multiple resources in a single Forseti installation. See [Configure Inventory]({% link _docs/latest/configure/inventory/index.md %})
   for more details.

1. Saving changes.
   1. Save the changes to `main.tf` file.
   1. Run command `terraform plan` to see the infrastructure plan. 
   1. Run command `terraform apply` to apply the infrastructure build.
   
When you run Forseti again, all the resources from the target root
will be collected in Inventory and audited.

## Configure Forseti to Run on Projects

As an alternative, you can use the `composite_root_resources` configuration to 
include one or more resources from GCP resource hierarchy in a single Forseti 
installation.
See [Configure Inventory]({% link _docs/latest/configure/inventory/index.md %})
for more details.

For example: `composite_root_resources:` `["projects/<foo_project1_id>", "projects/<foo_project2_id"]`

1. Edit `main.tf` and set `composite_root_resources` variable to the target 
projects: `["projects/<foo_project1_id>", "projects/<foo_project2_id"]`.

1. Saving changes.
   1. Save the changes to `main.tf` file.
   1. Run command `terraform plan` to see the infrastructure plan. 
   1. Run command `terraform apply` to apply the infrastructure build.

When you run Forseti again, all the resources from the target root
will be collected in Inventory and audited.
