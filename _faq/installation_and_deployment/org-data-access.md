---
title: Why is Forseti only reading data from one project?
order: 5
---
{::options auto_ids="false" /}

If Forseti is reading data from only one project, your Forseti service account 
might have access only to that particular project. To get read access to all of 
the projects under your organization, add the service account to the
organization IAM policy with the 
[required roles]({% link _docs/guides/best-practices.md %}#service-account-for-forseti-security).
Your Organization Admin should be able to help you with that.
