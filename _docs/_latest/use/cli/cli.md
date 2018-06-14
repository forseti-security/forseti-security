---
title: CLI
order: 101
---

# {{ page.title }}

Forseti 2.0 provides a convenient CLI (command line interface) client
that can be used to operate the various functionalities in Forseti:
build inventory, create models, use explain, perform scanning, and
send notifications.

---

## Access

CLI users can be non-admin users, and should not have access to the highly
elevated privileges that Forseti is permissioned with. So to prevent CLI users
from gaining Forseti's privilege, the CLI is deployed to its own VM,
and communicates with the Server via gRPC. 

Access to the CLI VM is managed by [OS Login](https://cloud.google.com/compute/docs/instances/managing-instance-access) roles.

* Users in the internal domain must be granted `compute.osLogin` role.
* Users from external domains must be granted `compute.osLoginExternalUser` role. 

Once granted these roles, CLI users will then gain SSH access to the CLI VM.
Forseti Config lets you set the configuration of the CLI.

You can learn more about the [client-server architecture of Forseti]({% link _docs/latest/concepts/architecture.md %}).

## Show the current local configuration

```bash
forseti config show
```

The command above will output the current local configuration. 

### Resetting the local configuration

```bash
forseti config reset
```

The command above will reset local configuration back to it's original state.

### Formatting the CLI output

```bash
forseti config format <FORMAT>
```

The command above will update the output format of the CLI to `<FORMAT>`.

* `<FORMAT>`
  * **Description**: The CLI output format.
  * **Valid values**: one of `text` or `json`.

### Setting the server endpoint

```bash
forseti config endpoint <IP_ADDRESS>:50051
```

The command above will set the IP address the CLI uses to communicate to the server.

## What's Next

See the left-bar to learn how to use the CLI commands for specific components. 
