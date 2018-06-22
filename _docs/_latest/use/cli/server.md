---
title: Server
order: 106
---

# {{ page.title }}

This page describes how to use the command-line interface (CLI)
to request the server to retrieve and use new settings.

---

## Running Forseti Server

### Getting the current server configuration

The following command will output the configuration that Forseti
server is currently using:

```bash
forseti server configuration get
```

### Reloading the current server configuration

The following command forces the server to reload its configuration:

```bash
forseti server configuration reload <PATH_TO_CONFIG_FILE>
```

Where `<PATH_TO_CONFIG_FILE>` is an optional path to the Forseti
configuration `yaml` file. If not specified, the default path will
be used. If you specify a path, make sure the server has access to
it, like a path in the server VM or a Cloud Storage path that starts
with gs://.

### Getting the current log level of the server

The following command above outputs the current log level of the server:

```bash
forseti server log_level get
```

### Setting the server log level

The following command will set the log level of the server:

```bash
forseti server log_level set <LOG_LEVEL>
```

Where `<LOG_LEVEL>` is the log level of the server as one of
`debug`, `info`, `warning` or `error`.
