---
title: How is Forseti able to read data from all my projects?
order: 2
---
{::options auto_ids="false" /}

Forseti uses a service account which is granted roles on the organization 
Cloud IAM policy. Because roles are hierarchical in GCP, if someone has 
a Cloud IAM role the organization level, the role is inherited by lower levels, 
like the folder or project. For example, if you grant the "Browser" role 
to someone on the organization, they will also be able to see folders and 
projects within the organization.

For more information, please refer to 
["Service account for Forseti Security"]({% link _docs/guides/forseti-service-accounts.md %}#service-account-for-forseti-security).
