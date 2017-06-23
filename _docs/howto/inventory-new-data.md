---
title: Collection and Storing New Data in Forseti Inventory
order: 6
---
#  {{ page.title }}

This page describes how to modify Forseti Inventory to collect and store new
data types.

## Collecting and storing new data

To add new GCP resource types to Forseti Inventory, follow the process below:

  1. Define a new table schema for the *flattened* data you'll store. Each
  field of data you retrieve from an API should correspond to a column in the
  table schema.
  1. Define a new table schema for the *raw* data you'll store. The GCP API
  sends data stored as JSON.
  1. Create a
  [pull request](https://help.github.com/articles/creating-a-pull-request/) to
  add initial table schema. To learn more, refer to this
  [example pull request](https://github.com/GoogleCloudPlatform/forseti-security/pull/159).
  1. After you merge the table schema pull request, create a
  [pipeline](https://github.com/GoogleCloudPlatform/forseti-security/tree/master/google/cloud/security/inventory/pipelines)
  to fetch your data. If Forseti isn't currently collecting the data you want
  from GCP, you'll need to extend Forseti's API support for
  [Google Cloud APIs](https://cloud.google.com/apis/docs/overview).
  1. Update your pipeline_requirements_map.py to reference the configuration in
  inventory_conf.yaml.
  1. Flatten the data collected from your API so you can store it in a CSV or
  normalized storage system. Learn more about [flattening the data structure](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/inventory/pipelines/load_projects_pipeline.py#L32).
  1. Load the flattened data into the database table.

For an example of the steps above, see this pull request for
[adding fetching and storing of groups](https://github.com/GoogleCloudPlatform/forseti-security/pull/165).
