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
1. if you are Project Admin, and you want to run Forseti on projects
that are only owned by you.

Inventory, Data Model, and Scanner will be supported for use on these subset
of resources, but Explain will not be supported.

## How to Install

Run the Forseti [Installer]({% link _docs/v2.22/setup/install.md %}).

By default, the installer will try to assign org-level roles. If you are not
an Org Admin, there will be errors, but you can safely disregard, as you will
manually assign the correct roles later.

## Configure Forseti to Run on a Folder

1. Edit `forseti_conf_server.yaml` and point the `root_resource_id`
to the target folder:
`folders/<foo_folder_id>`.

1. **NEW for version 2.12.0+**: You can use the `composite_root_resources`
   configuration to include multiple resources in a single Forseti installation.
   See [Configure Inventory]({% link _docs/v2.22/configure/inventory/index.md %})
   for more details.

1. If Forseti was installed with Org Admin credentials, then the org-level
   roles will be inherited on the folder-level.

1. If Foresti was not installed with Org Admin credentails, then you need
   to grant the Forseti server service account to have the same roles on the
   target resources, as was [originally granted on the
   organization]({% link _docs/v2.22/concepts/service-accounts.md %}#the-server-service-account).

1. Saving changes.
   1. Save the changes to `forseti_conf_server.yaml` file.
   1. Upload `forseti_conf_server.yaml` [to GCS bucket]({% link _docs/v2.22/configure/general/index.md %}#moving-configuration-to-cloud-storage).

1. Use the updated configuration.
   1. SSH to the Forseti server VM.
   1. Use sudo gsutil to copy the `forseti_conf_server.yaml` file from GCS
   bucket to `/home/ubuntu/forseti-security/configs/`.
   1. Make the server [reload the updated configuration]({% link _docs/v2.22/use/cli/server.md %}).

## Configure Forseti to Run on Projects

**NEW for version 2.12.0+**: As an alternative, you can use the
`composite_root_resources` configuration to include multiple resources in a
single Forseti installation.
See [Configure Inventory]({% link _docs/v2.22/configure/inventory/index.md %})
for more details.

1. This assumes that Forseti is not installed with Org Admin credential, and
you want Forseti to run on projects that you own. If Forseti is installed
with Org Admin credential, then all the resources in the organization
will be returned.

1. Leave the `root_resource_id` pointed to the organization that the Installer
inferred from the environment.

1. Grant project viewer role to the Forseti server service account,
on the projects that you own.

When you run Forseti again, all the resources from the target root
will be collected in Inventory and audited.
