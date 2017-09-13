---
title: Why does Forseti store the G Suite private key in the Compute Engine instnce?
order: 1
---
{::options auto_ids="false" /}

The 
[Admin API](https://developers.google.com/admin-sdk/directory/v1/guides/delegation), 
which performs the G Suite Groups data retrieval, uses methods from an OAuth library 
which expect the private key to be local to where the code is running. 
To minimize G Suite service account access, don't assign any Cloud IAM roles to it 
and only grant the Groups/Group Members Read-Only scope in G Suite. 
To learn more, see the 
[Best Practices]({% link _docs/guides/best-practices.md %}#gsuite-groups-service-account) page.
