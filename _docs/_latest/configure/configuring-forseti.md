---
title: Configuring Forseti
order: 202
---

# {{ page.title }}

This page describes how to configure Forseti once it's set up. Forseti configurations
are global and module-specific settings such as the following:

-   `global`: configurations that are used by multiple modules such as database
    configurations.
-   `inventory`: configurations that are used only by Forseti Inventory, such as
    specifying the inventory pipelines to enable.
-   `scanner`: configurations that are used only by Forseti Scanner, such as
    specifying which scanners to enable.
-   `notifier`: configurations that are used only by Forseti Notifier, such as
    specifying which notifications to enable.

Configurations are centrally maintained in
forseti-security/configs/forseti_conf.yaml file that's organized into
module-specific sections.

## Configuring settings

To set up your configuration, you'll edit
[forseti_conf.yaml sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/configs/forseti_conf.yaml.sample)
and save it as `forseti_conf.yaml`. For convenience, you can maintain different
versions of this file to support multiple configurations of Forseti.

-   `forseti_conf_prod.yaml`
-   `forseti_conf_staging.yaml`

To specify the location of the configuration file for Forseti to read and use
at run-time, use the `--forseti_config` flag. Following is an example for
running Forseti Inventory:

```
forseti_inventory --forseti_config path/to/forseti_conf.yaml
```

If you change a configuration, such as by changing which pipeline or scanner to
run, you'll need to restart the appropriate module so it picks up the new
configuration change.

### Minimum configuration

{% include docs/latest/min_conf_settings.md %}

### Configuring Inventory

Forseti Inventory runs in batch mode, executing each inventory
pipeline serially for each run. To specify which pipelines to run:

1.  Open `forseti-security/configs/forseti_conf.yaml`.
1.  Navigate to the `inventory` > `pipelines` section.
1.  Edit the `enabled` property for the appropriate pipelines.
    `true` enables the pipeline, and `false` disables the pipeline.

When you're finished making changes, run the following command with your
updated configuration:

```
forseti_inventory --forseti_config path/to/forseti_conf.yaml
```

### Configuring Scanner

Forseti Scanner runs in batch mode, executing each scanner serially 
for each run. To modify the scanner settings:

1. Open `forseti-security/configs/forseti_conf.yaml`.
1. Navigate to the `scanner` > `scanners` section.
1. Edit the `enabled` property for the appropriate pipelines.
   `true` enables the pipeline, and `false` disables the pipeline.
1. Forseti Scanner can save output to CSV files. To specify an output 
   location, specify the `output_path` location (either on the local 
   filesystem or in GCS) where you want to save the CSV.
1. Specify the path of the rule files (either on the local filesystem
   or in GCS).

When you're finished making changes, run the following command with your
updated configuration:

 ```
 forseti_scanner --forseti_config path/to/forseti_conf.yaml
 ```
 
Forseti Scanner is dependent on specific Inventory pipelines. To learn about
the available scanners and dependencies, see
[Scanner Specifications]({% link _docs/latest/configure/scanner/descriptions.md %}).
 
 
### Configuring Notifier

Forseti Notifier can currently send notifications for scanner violations. The 
following options are available:

* Email notifications via SendGrid -- This sends the scanner violation data to 
  a specific email recipient.
* Upload violations CSV to GCS -- This uploads the scanner violation data to GCS.
* Slack webhook -- This invokes a Slack webhook for each scanner violation found. 
  Configure a webhook in your organization's Slack settings and set the `webhook_url`.

You can invoke the Forseti Notifier with the following command:

```
forseti_notifier --forseti_config path/to/forseti_conf.yaml
```

### Move Configuration to GCS

If you are running Forseti on GCP, you should copy your edited forseti_conf.yaml to 
your GCS `SCANNER_BUCKET`. When Forseti runs again (via cronjob), it will execute a
script that downloads the latest conf and rules files.

Use the following commands to copy your conf and rules files to GCS:

```
gsutil cp configs/forseti_conf.yaml gs://YOUR_SCANNER_BUCKET/configs/forseti_conf.yaml
```

Next, edit your rules and copy the rules directory to the GCS `SCANNER_BUCKET`:

```
gsutil cp -r rules gs://YOUR_SCANNER_BUCKET/
```
