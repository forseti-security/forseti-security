---
title: Why run Forseti in its own separate project?
order: 4
---
{::options auto_ids="false" /}

Following are the reasons you should run Forseti in a separate project:

* Google Cloud Platform (GCP) API quota  
  * Setting Forseti up in a separate project ensures that Forseti has the
  quota it needs for API calls and managing service accounts and roles.

* Project permissions  
  * Setting Forseti up in a separate project restricts who has access to your 
  Forseti-related permissions and resources.

* Forseti clean up  
  * Setting Forseti up in a separate project allows you to easily clean up your
  Forseti-related data by deleting the project. Clean up includes the Compute
  Engine instance, Cloud SQL instance, Cloud Storage bucket, service accounts,
  and Cloud IAM policies.
