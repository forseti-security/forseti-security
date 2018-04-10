---
title: Forseti
---

# {{ page.title }}

This page describes how to configure Forseti after it's set up. Forseti configurations
are global and module-specific settings such as the following:

-   [`global`]: configurations that are used by multiple modules such as SendGrid API key,
    G Suite admin account, and email recipients.
-   [`scanner`]({% link _docs/latest/configure/scanner/index.md %}): configurations that are used only by Forseti Scanner, such as
    specifying which scanners to enable.
-   [`notifier`]({% link _docs/latest/configure/notifier/index.md %}): configurations that are used only by Forseti Notifier, such as
    specifying which notifications to enable.

Configurations are centrally maintained in the
`forseti-security/configs/server/forseti_server_conf.yaml` file that's organized into
module-specific sections.

## Configuring settings

To set up your configuration, you'll edit
[forseti_server_conf.yaml.sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/configs/server/forseti_conf_server.yaml.sample)
and save it as `forseti_server_conf.yaml`. For convenience, you can maintain different
versions of this file to support multiple configurations of Forseti.

-   `forseti_server_conf_prod.yaml`
-   `forseti_server_conf_staging.yaml`


### Moving Configuration to Cloud Storage

If you are running Forseti on Google Cloud Platform (GCP), copy your edited forseti_server_conf.yaml to
your Forseti Cloud Storage bucket. When Forseti runs again (via cronjob), it will execute a
script that downloads the latest conf and rules files.

Use the following commands to copy your conf and rules files to Cloud Storage:

```
gsutil cp configs/forseti_conf.yaml gs://YOUR_FORSETI_GCS_BUCKET/configs/server/forseti_server_conf.yaml
```
