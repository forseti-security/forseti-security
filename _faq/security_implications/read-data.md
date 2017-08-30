---
title: How is Forseti able to read data from all my projects?
order: 2
---
{::options auto_ids="false" /}

Forseti uses a service account which is granted roles on the organization IAM policy. Because roles are hierarchical in GCP, any role that someone has on the organization level IAM will also be inherited on a lower level, such as at the folder or project level. For example, if you grant the "Browser" role to someone on the organization, they will also be able to see folders and projects within the organization.

For more information, please refer to ["Service account for Forseti Security"]({% link _docs/guides/best-practices.md %}#service-account-for-forseti-security).
