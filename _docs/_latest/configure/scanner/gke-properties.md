---
title: Google Kubernetes Engine Properties Rules
order: 345 
---

# {{ page.title }}

## Description

Kubernetes Engine clusters have a wide-variety of options.  You might
want to have standards so your clusters are deployed in a uniform
fashion.  Some of the options can introduce unnecessary security
risks.  The KE scanner allows you to write rules that check arbitrary
cluster properties for violations.  It supports the following
features:

* Any cluster property can be checked in a rule by providing a
  JMESPath expression that extracts the right fields.
  + See http://jmespath.org/ for a tutorial and detailed specifications.
* Rules can be whitelists or a blacklists.

You can find example rules in the
[`ke_scanner_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/ke_scanner_rules.yaml)
file.  The only rule enabled by default checks that logging is
enabled.  Check out some of the commented-out rules for more
advanced ideas.

This scanner is disabled by default, you can enable it in the
`scanner` section of your configuration file.

## Rule definition

```yaml
rules:
  - name: logging should be enabled
    resource:
      - type: project
        resource_ids:
          - '*'
    key: loggingService
    mode: whitelist
    values:
      - logging.googleapis.com
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String, you can use `*` to match for all.

* `key`
  * **Description**: A JMESPath expression that extracts values from
    the JSON representation of a GKE cluster.

    *Tip*: to find the JSON representation of your cluster use
    `gcloud --format=json container clusters describe <name>`
  * **Valid values**: String, must be a well-formed
    [JMESPath](http://jmespath.org/) expression.

* `mode`
  * **Description**: Choose whether or not the list of values will be
    interpreted as a whitelist or a blacklist.
  * **Valid values**: String.  Must be `whitelist` or `blacklist`.

* `values`
  * **Description**: The list of values that the rule looks for.
    * If `mode` is set to `whitelist`, the rule generates a violation
      if the value extracted from a cluster is NOT on this list.
	* If `mode` is set to `blacklist`, the rule generates a violation
      if the value extracted from a cluster IS on the list.
  * **Valid values**: A list of any valid YAML values.

    *Tip*: Pay attention to the data types that you enter here.  If
    the JMESPath expression in `key` extracts an integer, you probably
    want integers in this list.  Similarly, if the expression extracts
    a list of values, you need to provide lists.
