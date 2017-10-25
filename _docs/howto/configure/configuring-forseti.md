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

## Setting up configurations

To set up your configuration, you'll edit
[forseti_conf.yaml sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/configs/forseti_conf.yaml.sample)
and save it as `forseti_conf.yaml`. For convenience, you can maintain different
versions of this file to support running different forseti instances.

-   `forseti_conf_prod.yaml`
-   `forseti_conf_staging.yaml`
-   `forseti_conf_john.yaml`
-   `forseti_conf_jane.yaml`

To specify the location of the configuration file for Forseti to read and use
at run-time, use the `--forseti_config` flag. Following is an example for
Forseti Inventory:

```
forseti_inventory --forseti_config path/to/forseti_conf.yaml
```

If you change a configuration, such as by changing which pipeline or scanner to
run, you'll need to restart the appropriate module so it picks up the new
configuration change.

### Configuring Inventory

{% include docs/howto/config_inventory.md %}

#### Setting up batch mode

You can run Forseti Inventory in batch mode to execute multiple inventory
pipelines to in the same run. To specify which pipelines to run:

1.  Open `forseti-security/configs/forseti_conf.yaml`.
1.  Navigate to the `inventory: pipelines` section.
1.  Edit the `enabled` flag for the appropriate pipelines. Set the flag to
    `true` to enable a pipeline, or `false` to disable the pipeline.

When you're finished making changes, run the following command with your
updated configuration:

```
forseti_inventory --forseti_config path/to/forseti_conf.yaml
```

### Configuring Scanner

You can run Forseti Scanner in batch mode to execute multiple scanners in the
same run. To specify which scanners to run in a batch:

1.  Open `forseti-security/configs/forseti_conf.yaml`.
1.  Navigate to the `scanner: scanners` section.
1.  Forseti Scanner can save outputs to CSV files. To specify an output
location,  specify the `output_path` location (either on the local filesystem
or in GCS) where you want to save the CSV
1.  Specify the path of the rule files (either on the local filesystem
or in GCS).
1.  Edit the `enabled` flag for the appropriate scanners. Set the flag to `true`
    to enable a scanner, or `false` to disable the scanner.

When you're finished making changes, run the following command with your
updated configuration:

 ```
 forseti_scanner --forseti_config path/to/forseti_conf.yaml
 ```
 
 Some scanners are dependent on specific Inventory pipelines. To learn about
 the available scanners and dependencies, see
 [Scanner specifications]({% link _docs/quickstarts/scanner/descriptions.md %}).
 
 
### Configuring Notifier

Coming soon.


## Updating configuration for GCP deployments
If you've updated a forseti_conf.yaml for a GCP deployment, refer to 
["GCP Deployment"]({% link _docs/howto/deploy/gcp-deployment.md %}#move-configuration-to-gcs)
for instructions how to copy it to the bucket associated with your deployment. After 
copying your conf file to the bucket, the next time Forseti runs, it will download the
new configuration automatically.
