---
title: Server
order: 008
---

# {{ page.title }}

Forseti Server is tool to retrieve and update the server settings.

## Running Forseti Server

### Getting the current server configuration

```bash
$ forseti server configuration get 
```

The command above will output the configuration that is current used by Forseti server.

### Reloading the current server configuration

```bash
$ forseti server configuration reload <PATH_TO_CONFIG_FILE> 
```

The command above will have the server reload its configuration.

* `<PATH_TO_CONFIG_FILE>` 
  * **Description**: (Optional) The path to the forseti configuration yaml file. If not specified, 
  the default path will be used. Note: Please specify a path that the server has access to (e.g. 
  a path in  the server vm or a gcs path starts with gs://).

### Getting the current log level of the server

```bash
$ forseti server log_level get
```

The command above output the current log level of the server.

### Setting the server log level

```bash
$ forseti server log_level set <LOG_LEVEL>
```

The command above will set the log level of the server.

* `<LOG_LEVEL>`
  * **Description**: The log level of the server.
  * **Valid values**: one of `debug`, `info`, `warning` or `error`.
