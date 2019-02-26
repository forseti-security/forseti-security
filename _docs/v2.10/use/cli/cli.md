---
title: Command-line interface
order: 101
---

# {{ page.title }}

Forseti 2.0 provides a convenient command-line interface (CLI) client
that you can use to operate the various functionalities in Forseti:
build inventory, create models, use explain, perform scanning, and
send notifications.

---

## Access

CLI users can be non-admin users, and should not have access to the highly
elevated privileges that Forseti is permissioned with. To prevent CLI users
from gaining Forseti's privilege, the CLI is deployed to its own VM,
and communicates with the Server via gRPC.

Access to the CLI VM is managed by [OS Login](https://cloud.google.com/compute/docs/instances/managing-instance-access) roles.

* Users in the internal domain must be granted `compute.osLogin` role.
* Users from external domains must be granted `compute.osLoginExternalUser` role.

When a CLI user has these roles, they gain SSH access to the CLI VM.
Forseti Config enables you to set the CLI configuration.

For more information, see the [client-server architecture of Forseti]({% link _docs/v2.10/concepts/architecture.md %}).

## Show the current local configuration

The following command outputs the current local configuration:

```bash
forseti config show
```

### Resetting the local configuration

The following command resets the local configuration back to its original state:

```bash
forseti config reset
```

### Formatting the CLI output

The following command will update the output format of the CLI to `<FORMAT>`:

```bash
forseti config format <FORMAT>
```

Where `<FORMAT>`defines the CLI output format as `text` or `JSON`.

### Setting the server endpoint

The following command sets the IP address the CLI uses to communicate to the server:

```bash
forseti config endpoint <IP_ADDRESS>:50051
```

## What's Next

*  To learn how to use the CLI commands for specific components, see the other [CLI guides]({% link _docs/v2.10/use/cli/index.md %}).
