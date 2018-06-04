---
title: How to install and run Forseti without Org Access.
order: 6
---
{::options auto_ids="false" /}

Although Forseti is designed to install and run out-of-the box with complete
org access, it is possible to install Forseti without being an org admin and
then manually give Forseti the permissions to inventory and audit specific
projects.  These projects must be standalone and can not be under folders.

1. User is not org admin, nor has access to an org admin to give org access to
Froseti.

1. Non-org admin user runs the Forseti installer. The installer will attempt
to assign org-level roles, but those can be ignored.

1. The installer will create all the necessary Forseti resources: Forseti
project, VM instances, CloudSQL db, and most importantly the
service accounts.

1. Grant the Forseti server service account with project viewer role
on the specific projects that you want Forseti to audit.

When you run the Forseti inventory again, you will see the project and all
the project resources collected in inventory.

