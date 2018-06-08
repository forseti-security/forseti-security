---
title: How to install and run Forseti without Org Access.
order: 6
---
{::options auto_ids="false" /}

Although Forseti is designed to install and run out-of-the box with complete
org access, it is possible to install Forseti without being an org admin and
then manually give Forseti the permissions to inventory and audit subset of
resources by one specific folder or by projects that are standalone under
the org and not be under folders.

1. User is not org admin, nor has access to an org admin to give org access to
Froseti.

1. Non-org admin user runs the Forseti [installer]({% link _docs/latest/setup/install.md %}).
The installer will attempt to assign org-level roles without success, but\
those can be ignored.

1. The installer will create all the necessary Forseti resources: Forseti
project, VM instances, CloudSQL db, and most importantly the service accounts.

1. If you want to inventory all the resources in a folder,
edit the `forseti_conf_server.yaml` and point the `root_resource_id`
to the target folder: `folders/<foo_folder_id>`.  Be sure to force the server
to [reload the updated configuration]({% link _docs/latest/use/server.md %}).
[Grant the folder editor role](https://cloud.google.com/iam/docs/granting-changing-revoking-access)
to the forseti server service account, on the target folder.

1. If you want to inventory all the standalone projects under the org, no
update to `forseti_conf_server.yaml` is necessary.  Directly grant the project
viewer role to Forseti server service account, on the specific projects that
you want Forseti to inventory.

When you run the Forseti inventory again, you will see the project and all
the project resources collected in inventory.
