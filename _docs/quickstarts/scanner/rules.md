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
Forseti bucket or copy them to the `rules_path` (found in `forseti_conf.yaml`).

## Cloud IAM policy rules

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

## Google Groups rules

```yaml
- name: Allow my company users and gmail users to be in my company groups.
  group_email: my_customer
  mode: whitelist
  conditions:
    - member_email: '@MYDOMAIN.com'
    - member_email: '@gmail.com'
```

## GCS bucket ACL rules

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

## Cloud SQL rules

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

BigQuery scanner rules serve as blacklists.

```yaml
rules:
  - name: sample BigQuery rule to search for public datasets
    dataset_id: '*'
    special_group: '*'
    user_email: '*'
    domain: '*'
    group_email: '*'
    role: 'allAuthenticatedUsers'
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

## Forwarding rules

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
