---
title: Config
order: 007
---

# {{ page.title }}

Forseti Config is a tool for you to set the configuration of the CLI.

You can learn more about the client-server architecture of Forseti [here]({% link _docs/latest/concepts/architecture.md %}).

## Running Forseti Config

#### Show the current local configuration

```bash
$ forseti config show
```

The command above will output the current local configuration. 

#### Resetting the local configuration

```bash
$ forseti config reset
```

The command above will reset local configuration back to it's original state.

#### Formatting the CLI output

```bash
$ forseti config format <FORMAT>
```

The command above will update the output format of the CLI to `<FORMAT>`.

Possible values for `<FORMAT>` are `text` or `json`.

#### Setting the server endpoint

```bash
$ forseti config endpoint <IP_ADDRESS>:50051
```

The command above will set the IP address the CLI uses to communicate to the server.
