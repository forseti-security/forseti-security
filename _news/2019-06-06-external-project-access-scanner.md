---
title: External Project Access Scanner
author: Rehana Devani
---

With the release of the external project access scanner, data exfiltration can 
be mitigated by identifying users who have access to projects outside of your 
organization or folder. In GCP, the best practice is to use service accounts to
perform actions where a GCP user isn’t directly involved. The challenge here is 
that a service account only has permissions in the organization where Forseti is 
deployed. In other words, if Forseti is deployed in Organization A, it can’t see 
what projects a user has access to in Organization B.
 
This is where the concept of “delegated credentials” becomes incredibly useful.
Delegated credentials allow a service account to temporarily act as a user. 
After compiling a list of users in the organization, the service account 
impersonates each user with these delegated credentials. The scanner then 
obtains the list of projects to which each user has access, regardless of the 
organization node.

Read more about External Project Access Scanner and how the rules are 
configured on the [Google Cloud security blog post](https://cloud.google.com/blog/products/identity-security/help-stop-data-leaks-with-the-forseti-external-project-access-scanner).
