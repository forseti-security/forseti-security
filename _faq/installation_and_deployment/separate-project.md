---
title: Why run Forseti in its own separate project?
order: 4
---
{::options auto_ids="false" /}

Here are the three main reasons why you should run Forseti in a separate project.

* GCP API quota  
  * Setting Forseti up in a separate project ensures that Forseti has the necessary
  quota for API calls and managing service accounts and roles.

* Project permissions  
  * Setting Forseti up in a separate project restricts who has access to your 
  Forseti-related permissions and resources.

* Forseti clean up  
  * Setting Forseti up in a separate project allows you to clean up your Forseti-related 
  data (including comptue instance, Cloud SQL instance, GCS bucket, service accounts and 
  IAM policies.) easily by simply deleting the project.