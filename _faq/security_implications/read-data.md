---
title: How is Forseti able to read data from all my projects?
order: 2
---
{::options auto_ids="false" /}

Forseti uses a service account that is granted roles on the organization's
Cloud IAM policy. Because GCP roles are hierarchical, when someone has 
a Cloud IAM role at the organization level, child resources like folders and
projects inherit the role. For example, if you grant the "Browser" role 
to someone at the organization level, they will also be able to see folders and 
projects within the organization.

For more information, see 
[Service account for Forseti Security]({% link _docs/latest/concepts/service-accounts.md %}).
