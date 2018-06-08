---
title: Can I install and run Forseti without Org Access?
order: 6
---
{::options auto_ids="false" /}

Although Forseti is designed to install and run out-of-the box with complete
org access, you can install Forseti if you aren't an org admin. You'll then
manually give Forseti the permissions to inventory and audit a subset of
resources by one specific folder or by projects that are directly under
the org.

If you aren't an org admin and an org admin isn't available to grant org
access to Forseti, follow the process below:

   1. Edit `forseti_conf_server.yaml` and point the `root_resource_id`
to the target folder: `folders/<foo_folder_id>`.
   1. Force the server to [reload the updated configuration]({% link _docs/latest/use/server.md %}).
   1. [Grant the folder editor role](https://cloud.google.com/iam/docs/granting-changing-revoking-access) to the Forseti server service account, on the target folder.

1. To inventory all the projects directly under the org, directly grant the project
viewer role to Forseti server service account, on the specific projects that
you want Forseti to inventory.

When you run Forseti inventory again, all the projects and project resources
will be collected in Inventory.
