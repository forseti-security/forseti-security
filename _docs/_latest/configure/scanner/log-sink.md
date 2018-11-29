---
title: Log Sink Rules
order: 380
---

# {{ page.title }}

## Description

Alert or notify if a project does not have required log sinks. This scanner will also be able to check if the sink destination is correctly configured.

For examples of how to define scanner rules for log sink, see the
[`log_sink_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/log_sink_rules.yaml)
rule file.

## Rule definition

```yaml
rules:
  - name: 'Require BigQuery Audit Log sinks in all projects.'
    mode: required
    resource:
      - type: organization
        applies_to: children
        resource_ids:
          - org-1
    sink:
      destination: 'bigquery.googleapis.com/*'
      filter: 'logName:"logs/cloudaudit.googleapis.com"'
      include_children: '*'
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: One of `required`, `blacklist` or `whitelist`.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String.

* `applies_to`
  * **Description**: A list of resource types to apply this rule to.
  * **Valid values**: One of `self`, `children` or `self_and_children`.

* `sink`
  * `destination`
    * **Description**: The destination service. Where the exported log entries will go.
    * **Valid values**: String.

  * `filter`
    * **Description**: The logs filter. Determines which logs to export.
    * **Valid values**: String.
  
  * `include_children`
    * **Description**: Whether to include children. It is only relevant to sinks created for organizations or folders.
    * **Valid values**: String. One of `true`, `false` or `*`. `*` means the rule will match sinks with either true or false.
