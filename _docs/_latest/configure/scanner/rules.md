---
title: Defining Rules
order: 103
---

# {{ page.title }}

This page describes how to define rules for Forseti Scanner.

## Defining custom rules

You can find some starter rules in the
[rules](https://github.com/GoogleCloudPlatform/forseti-security/tree/dev/rules) 
directory. When you make changes to the rule files, upload them to your 
Forseti bucket under `forseti-server-xxxx/rules/` or copy them to the `rules_path` (found in `forseti_server_conf.yaml`).

## Cloud IAM policy rules

### Rule definition

Forseti Scanner recognizes the following rule grammar in YAML or JSON:

```yaml
rules:
  - name: $rule_name
    mode: $rule_mode
    resource:
      - type: $resource_type
        applies_to: $applies_to
        resource_ids:
          - $resource_id1
          - $resource_id2
          - ...
    inherit_from_parents: $inherit_from
    bindings:
      - role: $role_name
        members:
          - $member1
          - $member2
          ...
```

- **rules**: A sequence of rules.
- **mode**: A string of one of the following values:
  - **whitelist**: Allow the members defined.
  - **blacklist**: Block the members defined.
  - **required**: Defined members with the specified roles must be found in
    policy.
- **resource_type**: A string of one of the following values:
  - **organization**
  - **folder**
  - **project**
- **applies_to**: A string of one of the following values:
  - **self**: The rule only applies to the specified resource
  - **children**: The rule only applies to the child resources of the
    specified resource.
  - **self_and_children**: The rule applies to the specified resource and its
    child resources.
- **inherit_from_parents**: A boolean that defines whether a
  specified resource inherits ancestor rules.
- **bindings**: The [Policy Bindings](https://cloud.google.com/iam/reference/rest/v1/Policy#binding) to 
  audit. 
  - **role_name**: A
    [Cloud IAM role](https://cloud.google.com/compute/docs/access/iam) such as
    "roles/editor" or "roles/viewer".
    - You can also use wildcards, such as **roles/***. Refer to the starter rules or the
      unit tests directory for examples.
  - **members**: a list of Cloud IAM members. You can also use wildcards, 
    such as `serviceAccount:*@*gserviceaccount.com` (all service accounts) or
    `user:*@company.com` (anyone with an identity at company.com).

## Kubernetes Engine rules

### Rule definition

```yaml
rules:
  - name: Nodepool version not patched for critical security vulnerabilities
    resource:
      - type: organization
        resource_ids:
          - '*'
    check_serverconfig_valid_node_versions: false
    check_serverconfig_valid_master_versions: false
    allowed_nodepool_versions:
      - major: '1.6'
        minor: '13-gke.1'
        operator: '>='
      - major: '1.7'
        minor: '11-gke.1'
        operator: '>='
      - major: '1.8'
        minor: '4-gke.1'
        operator: '>='
      - major: '1.9'
        operator: '>='
 ```
- **name**: The description of your rule.
- **resource**: A mapping of resources that this rule applies to.
  - **type**: The type of resource, can be organization, folder, or project.
  - **resource_ids**: A list of one or more numeric ids to match, or '*' for all.
- **check_serverconfig_valid_node_versions**: If true, will raise a violation for any node pool
  running a version that is not listed as supported for the zone the cluster is running in.
- **check_serverconfig_valid_master_versions**: If true, will raise a violation for
  any cluster running an out of date master version. New clusters can only
  be created with a supported master version.
- **allowed_nodepool_versions**: Optional, if not included all versions are allowed.
  The list of rules for what versions are allowed on nodes.
  - **major**: The major version that is allowed.
  - **minor**: Optional, the minor version that is allowed. If not included, all minor versions are allowed.
  - **operator**: Optional, defaults to =, can be one of (=, >, <, >=, <=). The operator determines
    how the current version compares with the allowed version. If a minor version is not included,
    the operator applies to major version. Otherwise it applies to minor versions within a single major version.

### Enabling

To enable the Kubernetes Engine inventory, add the following to the inventory section in your forseti_confi.yaml file.

```yaml
inventory:
    pipelines:
        - resource: ke
          enabled: true
```

To enable the Kubernetes Engine scanner, add the followings to the scanner section in your forseti_conf.yaml file.

```yaml
scanner:
   scanners:
        - name: ke_version_scanner
          enabled: true
```

To enable the Kubernetes Engine notifier or blacklist notifier, add the followings to the notifier section in your forseti_conf.yaml file.

```yaml
    resources:
        - resource: ke_version_violations
          should_notify: true
          pipelines:
            # Upload violations to GCS.
            - name: gcs_violations_pipeline
              configuration:
                # gcs_path should begin with "gs://"
                gcs_path: gs://{__YOUR_SCANNER_BUCKET__}/scanner_violations
```

## Blacklist rules

### Rule definition

```yaml
rules:
  - blacklist: Emerging Threat blacklist
    url: https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
```

- **blacklist**: The name of your blacklist
- **url**: Url that contains a list of IPs to check against

### Enabling
To enable the blacklist scanner, add the followings to the scanner section in your forseti_conf.yaml file.

```yaml
scanner:
   scanners:
        - name: blacklist
          enabled: true
```

To enable the blacklist notifier, add the followings to the notifier section in your forseti_conf.yaml file.

```yaml
    resources:
        - resource: blacklist_violations
          should_notify: true
          pipelines:
            # Upload violations to GCS.
            - name: gcs_violations_pipeline
              configuration:
                # gcs_path should begin with "gs://"
                gcs_path: gs://{__YOUR_SCANNER_BUCKET__}/scanner_violations
```

## Google Groups rules

### Rule definition

```yaml
- name: Allow my company users and gmail users to be in my company groups.
  group_email: my_customer
  mode: whitelist
  conditions:
    - member_email: '@MYDOMAIN.com'
    - member_email: '@gmail.com'
```

## GCS bucket ACL rules

### Rule definition

```yaml
rules:
  - name: sample bucket acls rule to search for public buckets
    bucket: '*'
    entity: AllUsers
    email: '*'
    domain: '*'
    role: '*'
    resource:
        - resource_ids:
          - YOUR_ORG_ID / YOUR_PROJECT_ID
```

 - **name**: The description of your rule.
 - **bucket**: The bucket name you want to audit.
 - **entity**: The [ACL entity](https://cloud.google.com/storage/docs/access-control/lists)
   that holds the bucket permissions.
 - **email**: The email of the entity.
 - **domain**: The domain of the entity.
 - **role**: The access permission of the entity.
 - **resource**: The resource under which the bucket resides.

For more information, refer to the
[BucketAccessControls](https://cloud.google.com/storage/docs/json_api/v1/objectAccessControls#resource)
documentation.

## Cloud Audit Logging rules

### Rule definition

```yaml
rules:
  - name: sample audit logging rule for data access logging
    resource:
      - type: project
        resource_ids:
          - '*'
    service: 'storage.googleapis.com'
    log_types:
      - 'DATA_READ'
      - 'DATA_WRITE'
    allowed_exemptions:
      - 'user:user1@MYDOMAIN.com'
      - 'user:user2@MYDOMAIN.com'
 ```

- **name**: The description of your rule.
- **resource**: The resource under which the projects reside.
- **type**: A string of one of the following values:
  - **organization**
  - **folder**
  - **project**
- **resource_ids**: The resource IDs to which the rule applies. If resource
  type is `project` then an id of `'*'` applies the rule to all projects.
- **service**: The service on which logs must be enabled. The special value of
  `allServices` denotes audit logs for all services.
- **log_types**: The required log types. Each string is one of the following
  values:
  - **AUDIT_READ**
  - **DATA_READ**
  - **DATA_WRITE**
- **allowed_exemptions**: (optional) A list of allowed exemptions in the audit
  logs for this service.

## Cloud SQL rules

### Rule definition

```yaml
rules:
  - name: sample cloudsql rule to search for publicly exposed instances
    instance_name: '*'
    authorized_networks: '0.0.0.0/0'
    ssl_enabled: 'False'
    resource:
      - type: organization
        resource_ids:
          - YOUR_ORG_ID / YOUR_PROJECT_ID
 ```
 - **name**: The description of your rule.
 - **instance_name**: The Cloud SQL instance to which you want to apply the rule.
 - **authorized_networks**: The allowed network.
 - **ssl_enabled**: Whether SSL should be enabled (true or false).
 - **resource**: The resource under which the instance resides.

## BigQuery rules

### Rule definition

BigQuery scanner rules serve as blacklists.

```yaml
rules:
  - name: sample BigQuery rule to search for public datasets
    dataset_id: '*'
    special_group: 'allAuthenticatedUsers'
    user_email: '*'
    domain: '*'
    group_email: '*'
    role: '*'
    resource:
      - type: organization
        resource_ids:
          - YOUR_ORG_ID / YOUR_PROJECT_ID
```
- **name**: The description of your rule.
- **dataset_id**: The BigQuery dataset to which you want to apply the rule.
  A value of `*` applies the rule to all your datasets.
- **resource**: The resource under which the dataset resides.

The BigQuery Scanner rules specify entities that aren't allowed to access
your datasets. When you set a value of `*` for `special_group`, `user_email`,
`domain`, and `group_email`, Scanner checks to make sure that no entities can
access your datasets. If you specify any other value, Scanner only checks to
make sure that the entity you specified doesn't have access.

## Enabled APIs rules

### Rule definition

```yaml
rules:
  - name: sample enabled APIs whitelist rule
    mode: whitelist
    resource:
      - type: project
        resource_ids:
          - '*'
    services:
      - 'bigquery-json.googleapis.com'
      - 'compute.googleapis.com'
      - 'logging.googleapis.com'
      - 'monitoring.googleapis.com'
      - 'pubsub.googleapis.com'
      - 'storage-api.googleapis.com'
      - 'storage-component.googleapis.com'
 ```

- **name**: The description of your rule.
- **mode**: A string of one of the following values:
  - **whitelist**: Allow only the APIs listed in `services`.
  - **blacklist**: Block the APIs listed in `services`.
  - **required**: All APIs listed in `services` must be enabled.
- **resource**: The resource under which the projects reside.
- **type**: A string of one of the following values:
  - **organization**
  - **folder**
  - **project**
- **resource_ids**: The resource IDs to which the rule applies. If resource
  type is `project` then an id of `'*'` applies the rule to all projects.
- **services**: The list of services to whitelist/blacklist/require.

## Forwarding rules

### Rule definition

```yaml
rules:
  - name: Rule Name Example
    target: Forwarding Rule Target Example
    mode: whitelist
    load_balancing_scheme: EXTERNAL
    ip_protocol: ESP
    ip_address: "198.51.100.46"
```
- **name**: The description of your rule.
- **target**: The URL of the target resource to receive the matched traffic.
- **mode**: Rule matching mode. Currently just "whitelist".
- **load_balancing_scheme**: What the ForwardingRule will be used for,
  either `INTERNAL` or `EXTERNAL`.
- **ip_protocol**: The IP protocol to which this rule applies. Valid
  options are `TCP`, `UDP`, `ESP`, `AH`, `SCTP`, or `ICMP`.
- **ip_address**: The IP address for which this forwarding rule serves.

To learn more, see the
[ForwardingRules](https://cloud.google.com/compute/docs/reference/latest/forwardingRules)
documentation.

## IAP rules

### Rule definition

```yaml
rules:
  # custom rules
  - name: Allow direct access from debug IPs and internal monitoring hosts
    resource:
      - type: organization
        applies_to: self_and_children
        resource_ids:
          - YOUR_ORG_ID
    inherit_from_parents: true
    allowed_direct_access_sources: '10.*,monitoring-instance-tag'
```
- **name**: The description of your rule.
- **resource_type**: A string of one of the following values:
  - **organization**
  - **folder**
  - **project**
- **applies_to**: A string of one of the following values:
  - **self**: The rule only applies to the specified resource
  - **children**: The rule only applies to the child resources of the
    specified resource.
  - **self_and_children**: The rule applies to the specified resource and its
    child resources.
- **resource_ids**: The resource ID to which the rule applies.
- **inherit_from_parents**: A boolean that defines whether a
  specified resource inherits ancestor rules.
- **allowed_direct_access_sources**: Comma-separated list of globs that are
  matched against the IP ranges and tags in your firewall rules that allow
  access to services in your GCP environment.  
  
## Instance Network Interface rules

### Rule definition

```yaml
rules:
  # This rule helps with:
  # #1 Ensure instances with external IPs are only running 
  # on whitelisted networks
  # #2 Ensure instances are only running on networks created in allowed 
  # projects (using XPN)
  - name: all networks covered in whitelist
    project: '*'
    network: '*'
    is_external_network: True
    # this would be a custom list of your networks/projects.
    whitelist:
      master: 
        - master-1
      network: 
        - network-1 
        - network-2
      default:
        - default-1
```
- **name**: The description of your rule.
- **whitelist**: The whitelist describes which projects and networks for which
  VM instances can have external IPs. For example, the following values would
  specify that VM instances in project_01’s network_01 can have external IP
  addresses:
        
      project_01:
        - network_01
