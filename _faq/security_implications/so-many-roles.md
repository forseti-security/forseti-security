---
title: Why does Forseti require so many roles?
order: 3
---
{::options auto_ids="false" /}

Because the Forseti service account needs many types of permissions to read
certain data, you must grant
[grant Forseti the specific roles]({% link _docs/latest/concepts/service-accounts.md %})
that it needs to do its job.
