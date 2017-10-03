---
title: Why does Forseti require so many roles?
order: 3
---
{::options auto_ids="false" /}

We recommend 
[granting only the specific roles]({% link _docs/guides/forseti-service-accounts.md %}#service-accounts) 
that Forseti needs for reading data in GCP. Since there are many types of 
access that need to be granted for reading certain data, the Forseti service 
account must be granted those specific roles.
