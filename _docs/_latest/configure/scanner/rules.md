---
title: Defining Rules
order: 305
---

# {{ page.title }}

This page describes the Forseti scanners that are available, how they work, and
why they're important. You can
[configure Scanner]({% link _docs/latest/configure/scanner/index.md %}) to execute
multiple scanners in the same run.

---

## Defining custom rules

You can find some starter rules in the
[rules](https://github.com/GoogleCloudPlatform/forseti-security/tree/stable/rules)
directory. When you make changes to the rule files, upload them to your
Forseti bucket under `forseti-server-xxxx/rules/` or copy them to the `rules_path`
listed in `forseti_server_conf.yaml`.

## Cloud IAM Policy Rules

### Description

This section describes rules for Cloud Identity and Access Management (Cloud IAM).

Cloud IAM policies directly grant access on GCP. To ensure only authorized
members and permissions are granted in Cloud IAM policies, IAM policy scanner
supports the following:

* Whitelist, blacklist, and required modes.
* Define if the scope of the rule inherits from parents or just self.
* Access to specific organization, folder, project or bucket resource types.

For examples of how to define scanner rules for Cloud IAM policies, see the
[`iam_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/iam_rules.yaml)
rule file.

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

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: One of `whitelist`, `blacklist` or `required`.
  * **Note**:
    * `whitelist`: Allow the members defined.
    * `blacklist`: Block the members defined.
    * `required`: Defined members with the specified roles must be found in policy.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `applies_to`
    * **Description**: What resources to apply the rule to.
    * **Valid values**: One of `self`, `children` or `self_and_children`.
    * **Note**:
      * `self`: Allow the members defined.
      * `children`: Block the members defined.
      * `self_and_children`: The rule applies to the specified resource and its child resources.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String, you can use `*` to match for all.

* `inherit_from_parents`
  * **Description**: A boolean that defines whether a specified resource inherits ancestor rules.
  * **Valid values**: One of `true` or `false`.

* `bindings`
  * **Description**: The
  [Policy Bindings](https://cloud.google.com/iam/reference/rest/v1/Policy#binding) to audit.
    * `role`
      * **Description**: A [Cloud IAM role](https://cloud.google.com/compute/docs/access/iam).
      * **Valid values**: String.
      * **Example values**: `roles/editor`, `roles/viewer`
    * `members`
      * **Description**: A list of Cloud IAM members. You can also use wildcards.
      * **Valid values**: String.
      * **Example values**: `serviceAccount:*@*gserviceaccount.com` (all service accounts) or
        `user:*@company.com` (anyone with an identity at company.com).


## Kubernetes Engine Version Rules

### Description

Kubernetes Engine clusters running on older versions can be exposed to security
vulnerabilities, or lack of support. The KE version scanner can ensure your
Kubernetes Engine clusters are running safe and supported versions.

For examples of how to define scanner rules for your Kubernetes Engine versions, see the
[`ke_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/ke_rules.yaml)
file.

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

* `check_serverconfig_valid_node_versions`
  * **Description**: If true, will raise a violation for any node pool running a version
  that is not listed as supported for the zone the cluster is running in.
  * **Valid values**: One of `true` or `false`.

* `check_serverconfig_valid_master_versions`
  * **Description**: If true, will raise a violation for any cluster running an out of
  date master version. New clusters can only be created with a supported master version.
  * **Valid values**: One of `true` or `false`.

* `allowed_nodepool_versions`
  * **Description**: Optional, if not included all versions are allowed.
  The list of rules for what versions are allowed on nodes.
    * `major`
      * **Description**: The major version that is allowed.
      * **Valid values**: String.
      * **Example values**: `1.6`, `1.7`, `1.8`

    * `minor`
      * **Description**: Optional, the minor version that is allowed. If not included, all minor
      versions are allowed.
      * **Valid values**: String.
      * **Example values**: `11-gke.1`, `12-gke.1`

    * `operator`
      * **Description**: Optional, defaults to =, can be one of (=, >, <, >=, <=). The operator
      determines how the current version compares with the allowed version. If a minor version is
      not included, the operator applies to major version. Otherwise it applies to minor versions
      within a single major version.
      * **Valid values**: String.
      * **Example values**: `>=`

## Blacklist Rules

### Description

Virtual Machine (VM) instances that have external IP addresses can communicate
with the outside world. If they are compromised, they could appear in various
blacklists and could be known as malicious, such as for sending spam,
hosting Command & Control servers, and so on. The blacklist scanner audits
all of the VM instances in your environment and determines if any VMs
with external IP addresses are on a specific blacklist you've configured.

For examples of how to define scanner rules, see the
[`blacklist_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/blacklist_rules.yaml) rule file.

### Rule definition

```yaml
rules:
  - blacklist: Emerging Threat blacklist
    url: https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
```

* **blacklist**: The name of your blacklist.
* **url**: URL that contains a list of IPs to check against.

## Google Group Rules

### Description
Because groups can be added to Cloud Identity and Access Management (Cloud IAM)
policies, G Suite group membership can allow access on GCP. The group scanner
supports a whitelist mode, to make sure that only authorized users are members
of your G Suite group.

For examples of how to define scanner rules for your G Suite groups, see the
[`group_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/group_rules.yaml)
rule file.

### Definition

```yaml
- name: Allow my company users and gmail users to be in my company groups.
  group_email: my_customer
  mode: whitelist
  conditions:
    - member_email: '@MYDOMAIN.com'
    - member_email: '@gmail.com'
```

## Cloud Storage Bucket ACL Rules

### Description

Cloud Storage buckets have ACLs that can grant public access to your
Cloud Storage bucket and objects. The bucket scanner supports a blacklist mode,
to ensure unauthorized users don't gain access to your Cloud Storage bucket.

For examples of how to define scanner rules for your Cloud Storage buckets, see the
[`bucket_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/bucket_rules.yaml) rule file.

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

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `resource`
  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String, you can use `*` to match for all.

* `bucket`
  * **Description**: The bucket name you want to audit.
  * **Valid values**: String, you can use `*` to match for all.

* `entity`
  * **Description**: The [ACL entity](https://cloud.google.com/storage/docs/access-control/lists) that holds the bucket permissions.
  * **Valid values**: String.
  * **Example values**: `AllUsers`

* `email`
  * **Description**: The email of the entity.
  * **Valid values**: String, you can use `*` to match for all.

* `domain`
  * **Description**: The domain of the entity.
  * **Valid values**: String, you can use `*` to match for all.

* `role`
  * **Description**: The access permission of the entity.
  * **Valid values**: String, you can use `*` to match for all.

For more information, refer to the
[BucketAccessControls](https://cloud.google.com/storage/docs/json_api/v1/objectAccessControls#resource)
documentation.

## Cloud Audit Logging Rules

### Description

You can configure Cloud Audit Logging to save Admin Activity and Data Access for
Google Cloud Platform (GCP) services. The audit log configurations for a project,
folder, or organization specify which logs should be saved, along with members who
are exempted from having their accesses logged. The audit logging scanner detects
if any projects are missing a required audit log, or have extra exempted members.

For examples of how to define scanner rules for Cloud Audit Logging, see the
[`audit_logging_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/audit_logging_rules.yaml)
rule file.

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

* `service`
  * **Description**: The service on which logs must be enabled. The special value of `allServices` denotes audit logs for all services.
  * **Valid values**: String.
  * **Example values**: `allServices`, `storage.googleapis.com`

* `log_types`
  * **Description**: The required log types.
  * **Valid values**: One of `ADMIN_READ`, `DATA_READ` or `DATA_WRITE`.

* `allowed_exemptions`
  * **Description**: Optional, a list of allowed exemptions in the audit logs for this service.
  * **Valid values**: String.
  * **Example values**: `user:user1@MYDOMAIN.com`

## Cloud SQL Network Scanner Rule

### Description

Cloud SQL instances can be configured to grant external networks access. The
Cloud SQL scanner supports a blacklist mode, to ensure unauthorized users don't
gain access to your Cloud SQL instances.

For examples of how to define scanner rules for your Cloud SQL instances, see
the
[`cloudsql_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/cloudsql_rules.yaml)
rule file.

### Rule definition

```yaml
rules:
  - name: sample Cloud SQL rule to search for publicly exposed instances
    instance_name: '*'
    authorized_networks: '0.0.0.0/0'
    ssl_enabled: 'False'
    resource:
      - type: organization
        resource_ids:
          - YOUR_ORG_ID / YOUR_PROJECT_ID
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

* `instance_name`
  * **Description**: The Cloud SQL instance to which you want to apply the rule.
  * **Valid values**: String, you can use `*` to match for all.

* `authorized_networks`
  * **Description**: The allowed network.
  * **Valid values**: String.
  * **Example values**: `0.0.0.0/0`

* `ssl_enabled`
  * **Description**: Whether SSL should be enabled.
  * **Valid values**: One of `true` or `false`.

## BigQuery Dataset ACL Rules

### Description

BigQuery datasets have access properties that can publicly expose your datasets.
The BigQuery scanner supports a blacklist mode to ensure unauthorized users
don't gain access to your datasets.

For examples of how to define scanner rules for your BigQuery datasets, see the
[`bigquery_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/bigquery_rules.yaml)
rule file.

### Rule definition

BigQuery scanner rules can be blacklists or whitelists, for example:

```yaml
rules:
  - name: sample BigQuery rule to search for public datasets
    mode: blacklist
    resource:
      - type: organization
        resource_ids:
          - YOUR_ORG_ID / YOUR_PROJECT_ID
    dataset_ids: ['*']
    bindings:
      - role: '*'
        members:
          - special_group: 'allAuthenticatedUsers'
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

* `dataset_ids`
  * **Description**: List of BigQuery datasets to which you want to apply the rule.
  * **Valid values**: String, you can use `*` to match for all.

* `bindings`
  * **Description**: The BigQuery ACL rule bindings to bind members to a role.
    * `role`
      * **Description**: A [BigQuery ACL role](https://cloud.google.com/storage/docs/access-control/lists).
      * **Valid values**: One of `OWNER`, `WRITER` or `READER`.
    * `members`
      * **Description**: A list of members. You can also use an empty list. Only a single field must be set per member.
        * `domain` 
          * **Description**: Domain.
          *  **Valid values**: String.
        * `group_email`
          * **Description**: Group email.
          * **Valid values**: String.
        * `user_email`
          * **Description**: User email.
          * **Valid values**: String.
        * `special_group`
          * **Description**: Special group.
          * **Valid values**: String.

* `special_group`
  * **Description**: The special group. ***DEPRECATED, please use bindings instead.***
  * **Valid values**: String, you can use `*` to match for all.

* `domain`
  * **Description**: Domain. ***DEPRECATED, please use bindings instead.***
  * **Valid values**: String, you can use `*` to match for all.

* `role`
  * **Description**: Role. ***DEPRECATED, please use bindings instead.***
  * **Valid values**: One of `OWNER`, `WRITER` or `READER`.

* `group_email`
  * **Description**: Group email. ***DEPRECATED, please use bindings instead.***
  * **Valid values**: String, you can use `*` to match for all.

* `user_email`
  * **Description**: User email. ***DEPRECATED, please use bindings instead.***
  * **Valid values**: String, you can use `*` to match for all.

The BigQuery Scanner rules specify entities that are allowed or not allowed 
(depending on mode) to access your datasets. 
For blacklists, when you set a value of `*` for `special_group`, `user_email`,
`domain`, or `group_email`, the Scanner checks to make sure that no entities that 
have the field set can access your datasets. If you specify any other value, the 
Scanner only checks to make sure that the entity you specified doesn't have access.
For whitelists, the specified entity specifies who has access to your datasets.
Any entity that does not match a whitelist binding will be marked as a violation.

## Enabled APIs Rules

### Description

The Enabled APIs scanner detects if a project has appropriate APIs enabled. It
supports whitelisting supported APIs, blacklisting unsupported APIs, and
specifying required APIs that must be enabled.

For examples of how to define scanner rules for Enabled APIs, see the
[`enabled_apis_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/enabled_apis_rules.yaml)
rule file.

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

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: One of `whitelist`, `blacklist` or `required`.
  * **Note**:
    * `whitelist`: Allow only the APIs listed in `services`.
    * `blacklist`: Block the APIs listed in `services`.
    * `required`: All APIs listed in `services` must be enabled.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `applies_to`
    * **Description**: What resources to apply the rule to.
    * **Valid values**: One of `self`, `children` or `self_and_children`.
    * **Note**:
      * `self`: Allow the members defined.
      * `children`: Block the members defined.
      * `self_and_children`: The rule applies to the specified resource and its child resources.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String, you can use `*` to match for all.

* `services`
  * **Description**: The list of services to whitelist/blacklist/require.
  * **Valid values**: String.
  * **Example values**: `bigquery-json.googleapis.com`, `logging.googleapis.com`

## Load Balancer Forwarding Rules

### Description

You can configure load balancer forwarding rules to direct unauthorized external
traffic to your target instances. The forwarding rule scanner supports a
whitelist mode, to ensure each forwarding rule only directs to the intended
target instances.

For examples of how to define scanner rules for your forwarding rules, see the
[`forwarding_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/forwarding_rules.yaml)
rule file.

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

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `target`
  * **Description**: The URL of the target resource to receive the matched traffic.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: Current only support `whitelist` mode.
  * **Note**:
     * `whitelist`: Ensure each forwarding rule only directs to the intended target instance.

* `load_balancing_scheme`
  * **Description**: What the ForwardingRule will be used for.
  * **Valid values**: One of `INTERNAL` or `EXTERNAL`.

* `ip_protocol`
  * **Description**: The IP protocol to which this rule applies.
  * **Valid values**: One of `TCP`, `UDP`, `ESP`, `AH`, `SCTP`, or `ICMP`.

* `ip_address`
  * **Description**: The IP address for which this forwarding rule serves.
  * **Valid values**: String.
  * **Example values**: `198.51.100.46`

To learn more, see the
[ForwardingRules](https://cloud.google.com/compute/docs/reference/latest/forwardingRules)
documentation.

## Cloud IAP Rules

### Description

Cloud Identity-Aware Proxy (Cloud IAP) enforces access control at the network
edge, inside the load balancer. If traffic can get directly to the VM, Cloud IAP
is unable to enforce its access control. The IAP scanner ensures that firewall
rules are properly configured and prevents the introduction of other network
paths that bypass the normal load balancer to instance flow.

For examples of how to define scanner rules for Cloud IAP, see the
[`iap_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/iap_rules.yaml)
rule file.

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

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: One of `whitelist`, `blacklist` or `required`.
  * **Note**:
    * `whitelist`: Allow the members defined.
    * `blacklist`: Block the members defined.
    * `required`: Defined members with the specified roles must be found in policy.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `applies_to`
    * **Description**: What resources to apply the rule to.
    * **Valid values**: One of `self`, `children` or `self_and_children`.
    * **Note**:
      * `self`: Allow the members defined.
      * `children`: Block the members defined.
      * `self_and_children`: The rule applies to the specified resource and its child resources.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String, you can use `*` to match for all.

* `inherit_from_parents`
  * **Description**: A boolean that defines whether a specified resource inherits ancestor rules.
  * **Valid values**: One of `true` or `false`.

* `allowed_direct_access_sources`
  * **Description**:  Comma-separated list of globs that are matched against the IP ranges and tags in your
  firewall rules that allow access to services in your GCP environment.
  * **Valid values**: String.
  * **Example values**: `10.*,monitoring-instance-tag`

## Instance Network Interface Rules

### Description

VM instances with external IP addresses expose your environment to an
additional attack surface area. The instance network interface scanner audits
all of your VM instances in your environment, and determines if any VMs with
external IP addresses are outside of the trusted networks.

For examples of how to define scanner rules for network interfaces, see the
[`instance_network_interface_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/instance_network_interface_rules.yaml)
rule file.


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
       project-1:
        - network-1
       project-2:
        - network-2
        - network-2-2
       project-3:
        - network-3
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `project`
  * **Description**: Project id.
  * **Valid values**: String, you can use `*` to match for all.

* `network`
  * **Description**: Network.
  * **Valid values**: String, you can use `*` to match for all.

* `whitelist`
  * **Description**: The whitelist describes which projects and networks for which VM
  instances can have external IPs.
  * **Valid values**: project/networks pairs.
  * **Example values**: The following values would specify that VM instances in
  project_01’s network_01 can have external IP addresses:

    ```
    project_01:
    - network_01
    ```

## Lien Rules

### Description
Allow customers to ensure projects do not get deleted, by ensuring Liens for their projects exist and are configured correctly.

For examples of how to define scanner rules for lien, see the
[`lien_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/lien_rules.yaml)
rule file.

### Rule definition

```yaml
rules:
- name: Require project deletion liens for all projects in the organization.
  mode: required
  resource:
  - resource_ids:
    - org-1
    type: organization
  restrictions:
  - resourcemanager.projects.delete
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: Currently only supports `required`.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String.

* `restrictions`
  * **Description**: A list of restrictions to check for.
  * **Valid values**: Currently only supports `resourcemanager.projects.delete`.

## Location Rules

### Description
Allow customers to ensure their resources are located only in the intended locations. Set guards around locations as part of automated project deployment.

For examples of how to define scanner rules for location, see the
[`location_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/location_rules.yaml)
rule file.

### Rule definition

```yaml
rules:
  - name: All buckets in organization must be in the US.
    mode: whitelist
    resource:
      - type: organization
        resource_ids:
          - org-1
    applies_to:
      - type: 'bucket'
        resource_ids: '*'
    locations:
      - 'us*'
 - name: All buckets in organization must not be in EU.
    mode: blacklist
    resource:
      - type: organization
        resource_ids:
          - org-1
    applies_to:
      - type: 'bucket'
        resource_ids: '*'
    locations:
      - 'eu*'
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: One of `blacklist` or `whitelist`.

* `resource`
  * `type`
    * **Description**: The type of the resource the applies_to resources belong to.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: List of strings.

* `applies_to`
  * `type`
    * **Description**: The type of resource to apply the rule to.
    * **Valid values**: Currently only supports `bucket`.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: List of strings. A single wildcard string is also accepted.

* `locations`:
  * **Description**: A list of resource locations.
  * **Value values**: String. Supports wildcards. 
  * **Note**:
    * Due to differences in capitalization among resource locations, all resources locations will be lower cased before being matched.
    * Due to differences in region (europe-west1) vs multi regional (EU) naming, we recommend writing rules that can cover both (e.g. eu* instead of europe*).

## Log Sink rules

### Description

Alert or notify if a project does not have required log sinks. This scanner will also be able to check if the sink destination is correctly configured.

For examples of how to define scanner rules for log sink, see the
[`log_sink_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/log_sink_rules.yaml)
rule file.

### Rule definition

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

## Service Account Key Rules

### Description

It's best to periodically rotate your user-managed service account
keys, in case the keys get compromised without your knowledge. With the
service account key scanner, you can define the max age at which your service
account keys should be rotated. The scanner will then find any key that is older
than the max age.

For examples of how to define scanner rules for your service account keys, see the
[`service_account_key_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/service_account_key_rules.yaml)
file.


### Rule definitions

 ```yaml
 rules:
  # The max allowed age of user managed service account keys (in days)
  - name: Service account keys not rotated
    resource:
      - type: organization
        resource_ids:
          - '*'
    max_age: 100 # days
 ```

* `name`
  * **Description**: The name of the rule
  * **Valid values**: String.

* `type`
  * **Description**: The type of the resource this rule applies to.
  * **Valid values**: String, one of `organization`, `folder` or `project`.

* `resource_ids`
  * **Description**: The id of the resource this rule applies to.
  * **Valid values**: String, you can use `*` to match for all.

* `max_age`
  * **Description**: The maximum number of days at which your service account keys can exist before rotation is required.
  * **Valid values**: String, number of days.

## Kubernetes Engine Rules

### Description

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

### Rule definition

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

## Retention rules

### Overview

TODO: Provide an overview

### Rule definition

```yaml
rules:
  - name: All buckets in the organization should have a retention policy for 100 to 200 days.
    applies_to:
      - bucket
    resource:
      - type: organization
        resource_ids:
          - "123456789012"
    minimum_retention: 100 # days
    maximum_retention: 200 # days
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.
  
* `applies_to`
  * `type`
    * **Description**: The type of resource to apply the rule to.
    * **Valid values**: String, Currently only supports `bucket`.
    
* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder`, `project`
      or `bucket`.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String.

* `minimum_retention`
  * **Description**: The minimum number of days to remain data.
    Remove this entry if it is not needed.
  * **Valid values**: Integer, number of days.

* `maximum_retention`
  * **Description**: The maximum number of days for which your data
    can be retained. Remove this entry if it is not needed.
  * **Valid values**: Integer, number of days.

    *Tip*: The rule must include a minimum_retention, maximum_retention or both.
  
## Firewall Rules 

### Overview
Network firewall rules protect your network & organization by only allowing
desired traffic into and out of your network. The firewall rules scanner can
ensure that all your network's firewalls are properly configured.

For examples of how to define scanner rules for your firewall rules scanner, see the
[`firewall_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/firewall_rules.yaml)
rule file.

### Rule definition

TODO: Provide a definition
