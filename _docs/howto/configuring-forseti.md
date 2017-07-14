---
title: Configuring Forseti
order: 8
---

# {{ page.title }}

This page describes how to set up Forseti configurations. Forseti configurations
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
module-specific sections. A single central file makes it easy to find and
maintain all the configurations.

## Setting up configurations

To set up your configuration, you'll edit
[forseti_conf.yaml sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/configs/forseti_conf.yaml.sample)
and save it as `forseti_conf.yaml`. For convenience, you can maintain different
versions of this file to support running different forseti instances.

-   `forseti_conf_prod.yaml`
-   `forseti_conf_staging.yaml`
-   `forseti_conf_john.yaml`
-   `forseti_conf_jane.yaml`

To specify the location of the configuration file for a module to read and use
at run-time, use the `--forseti_config` flag. Following is an example for
Forseti Inventory:

```
forseti_inventory --forseti_config path/to/forseti_conf.yaml
```

If you change a configuration, such as by changing which pipeline or scanner to
run, you'll need to restart the appropriate module so it picks up the new
configuration change.


### Configuring Inventory

{% include _howto/config_inventory.md %}

#### Setting up batch mode

You can run Forseti Inventory in batch mode to execute multiple inventory
pipelines to in the same run. To specify which pipelines to run:

1.  Open `forseti-security/configs/forseti_confs.yaml`.
1.  Navigate to the `inventory` section.
1.  Edit the `enabled` flag for the appropriate pipelines. Set the flag to
    `true` to enable a pipeline, or `false` to disable the pipeline.

````
inventory:

    pipelines:
        - resource: appengine
          enabled: true
        - resource: backend_services
          enabled: true
        - resource: bigquery_datasets
          enabled: true
        - resource: buckets
          enabled: true
        - resource: buckets_acls
          enabled: true
        - resource: cloudsql
          enabled: true
        - resource: firewall_rules
          enabled: true
        - resource: folder_iam_policies
          enabled: true
        - resource: folders
          enabled: true
````

When you're finished making changes, run the following command to update your
`forseti_inventory` configuration:

````
forseti_inventory --config_path path/to/forseti_conf.yaml
````

### Configuring Scanner

You can run Forseti Scanner in batch mode to execute multiple scanners in the
same run. To specify which scanners to run in a batch:

1.  Open `forseti-security/configs/forseti_confs.yaml`.
1.  Navigate to the `scanner` section.
1.  Edit the `enabled` flag for the appropriate scanners. Set the flag to `true`
    to enable a scanner, or `false` to disable the scanner.

````
scanner:

    scanners:
        - name: bigquery
          enabled: true
        - name: bucket_acl
          enabled: true
        - name: cloudsql_acl
          enabled: true
        - name: group
          enabled: true
        - name: iam_policy
          enabled: true
````

When you're finished making changes, run the following command to update your
`forseti_scanner` configuration:

 ````
 forseti_scanner --config_path path/to/forseti_conf.yaml
 ````
