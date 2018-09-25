---
title: Running Forseti from Non-Organization Root
order: 100
---

# {{ page.title }}

By default, Forseti is designed to be installed and run with complete
organization access and with the organization as the root node in the GCP
resource hierarchy.

But, you also have the option to run Forseti even if you only own a subset
of resources, such as a specific folder, or projects that are directly under
the org. You will be able to inventory audit these subset of resources,
but not be able to use Explain.

## How to Install and Configure

Follow the process below:

   1. Run the Forseti [installer]({% link _docs/latest/setup/install.md %}).
   The installer will try to assign org-level roles, but you can safely ignore
   this. The installer will create all the necessary Forseti resources:
   VM instances, Cloud SQL database, Google Cloud Storage buckets, and service
   accounts.
   1. If you want Forseti to run from a folder, edit `forseti_conf_server.yaml`
   and point the `root_resource_id` to the target folder:
   `folders/<foo_folder_id>`. Grant the Forseti server service account to have
   the same roles on the target folder, as was [originally granted on the
   organization]{% link docs/latest/forseti-server-gcp-required-roles.md %}.
   1. If you want Forseti to run on projects that you own, leave the
   `root_resource_id` pointed to the organization. Grant project
   viewer role to the Forseti server service account, on these specific
   projects.
   1. Save the changes to `forseti_conf_server.yaml` file.
   1. Save `forseti_conf_server.yaml` to GCS bucket.
   1. Make the server to
   [reload the updated configuration]({% link _docs/latest/use/cli/server.md %}).

When you run Forseti again, all the resources from the target root
will be collected in Inventory and audited.
