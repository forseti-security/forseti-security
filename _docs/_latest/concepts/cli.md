---
title: CLI
order: 100
---

# {{ page.title }}

Forseti 2.0 provides a convenient CLI (commandline interface) client
that can be used to operate the various functionalities in Forseti:
build inventory, create models, use explain, perform scanning, and
send notifications.

## Access

CLI users can be non-admin users, and should not have access to the highly
elevated privileges that Forseti is permissioned with. So to prevent CLI users
from gaining Forseti's privilege, the CLI is deployed to its own VM,
and communicates with the Server via gRPC.  

Access to the CLI VM is managed by [OS Login](https://cloud.google.com/compute/docs/instances/managing-instance-access) roles.

* Users in the internal domain must be granted `compute.osLogin` role.
* Users from external domains must be granted `compute.osLoginExternalUser` role. 

Once granted these roles, CLI users will then gain SSH access to the CLI VM.

## What's Next

Learn how to use CLI commands.
