---
title: Why does Forseti require so many roles?
order: 3
---
{::options auto_ids="false" /}

Since there are many types of permissions that need to be granted for reading
certain data, the Forseti service account must be granted the specific roles
in order to have the permission to read the data.  We only 
[grant Forseti to have the specific roles]({% link _docs/latest/concepts/service-accounts.md %}) 
that it needs to do its job. 
