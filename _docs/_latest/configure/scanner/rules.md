---
title: Defining Rules
order: 305
---

# {{ page.title }}

This page describes how to define rules for Forseti Scanner.

---

## Defining custom rules

You can find some starter rules in the
[rules](https://github.com/GoogleCloudPlatform/forseti-security/tree/stable/rules)
directory. When you make changes to the rule files, upload them to your
Forseti bucket under `forseti-server-xxxx/rules/` or copy them to the `rules_path`
listed in `forseti_server_conf.yaml`.

## BigQuery rules

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

## Blacklist rules

### Rule definition

```yaml
rules:
  - blacklist: Emerging Threat blacklist
    url: https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
```

* **blacklist**: The name of your blacklist.
* **url**: URL that contains a list of IPs to check against.

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
  
## Cloud IAM policy rules

This section describes rules for Cloud Identity and Access Management (Cloud IAM).

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
 
## Cloud IAP rules

This section describes rules for Cloud Identity-Aware Proxy (Cloud IAP).

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

## Cloud SQL rules

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
  
## Cloud Storage bucket ACL rules

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
  
## External Project Access rules

### Rule definitions
```yaml
rules:
- name: Only allow access to projects in my organization.
  allowed_ancestors:
  - organizations/{ORGANIZATION_ID}
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.
  
* `allowed_ancestors`
  * **Description**: The folder or organization that is allowed as an ancestor of a project.
  * **Valid values**: String, organizations/111 or folder/111.

* `users`
  * **Description**: * Optional. The users that are allowed access. Omitting this section would mean that the rule 
  applies to all users in the organization.
  * **Valid values**: String, user1@example.com.
  
## Firewall rules
Firewall Scanner rules can be `blacklist`, `whitelist`, `required`, or `matches` policies.  

### Example rule
```yaml
rules:
  - rule_id: 'prevent_allow_all_ingress_linux'
    description: 'Detect allow tcp and udp ingress from anywhere to all instances'
    mode: 'blacklist'
    match_policies:
      - direction: 'ingress'
        allowed: ['*']
        sourceRanges: ['0.0.0.0/0']
    verify_policies:
      - allowed:
        - IPProtocol: 'tcp'
          ports:
            - 'all'
      - allowed:
        - IPProtocol: 'udp'
          ports:
            - 'all'

# (...)

# You can chose to group your rules into rule_groups
# to apply them all at once on a resource
rule_groups:
  - group_id: 'default_rules'
    rule_ids:
      - 'prevent_allow_all_ingress_linux'

# (...)

# Bind your rules or rule groups to resources
org_policy:
  resources:
    - type: organization
      resource_ids:
        - YOUR_ORG_ID
      rules:
        group_ids:
          - 'default_rules'
        rule_ids:
          - 'prevent_allow_all_ingress_linux'
```

### Rule definition 
All modes share the same first-level rule structure:
* `rule_id`
  * **Description**: (*required*) The id of the rule.
  * **Valid values**: *String*.
  * **Note**:
     * You will use this value to reference the rule, it must be unique inside your file.
  * **Example values**: `prevent_allow_all_ingress`, `no_rdp_to_linux`

* `description`
  * **Description**: (*optional*) Your description of the rule.
  * **Valid values**: *String*.
  
* `mode`
  * **Description**: (*required*) The rule mode.
  * **Valid values**: *String*. One of `blacklist`, `whitelist`, `required`, `matches`.
  * **Modes description**:
     * `blacklist`: Ensure unauthorized firewall rules raise a violation.
     * `whitelist`: Only authorize the policies you define in the rule.
     * `required`: Check if firewall rules match **one** of the `match_policies` defined in the rule.
     * `matches`: Check if firewall rules match **all** of the `match_policies`defined in the rule.
  * **Notes**:
     * `whitelist` and `blacklist` rules require match and verify policies.
     * `required` and `matches` rules only require match policies.

* `match_policies` (*applicable to all modes*)
  * **Description**: Policies to filter which firewall rules to check when scanning.  
  * **Content**:
    * `direction`:
      * **Description**: The direction of the traffic for the rule.
      * **Valid values**: *String*. One of `ingress`, `egress`.
      * **Notes**:
        * For `ingress` traffic, it is NOT supported to specify `destinationRanges`.
        * For `egress` traffic, it is NOT supported to specify `sourceRanges` OR `sourceTags`.
    * `allowed`:
      * **Description**: A list of ALLOW rules specified by the firewall. Each rule specifies a protocol and port-range tuple that describes a permitted connection.
      * **Valid values**: List. You can use `*` to match for all.
      * **Notes**: Only one of `allowed` or `denied` can be used at the same time.
    * `denied`:
      * **Description**: A list of DENY rules specified by the firewall. Each rule specifies a protocol and port-range tuple that describes a denied connection.
      * **Valid values**: List. You can use `*` to match for all.
      * **Notes**: Only one of `allowed` or `denied` can be used at the same time.
    * `sourceRanges`:
      * **Description**: (*optional, 256 ranges max*) A list of source ranges.
      * **Valid values**: List of CIDR formatted IP ranges, e.g. `'0.0.0.0/0'`
    * `sourceServiceAccounts`:
      * **Description**: (*optional*) A list of service accounts if using source service accounts in firewall rules.
      * **Valid values**: List of service account email addresses, e.g. `'PROJECT@compute.gserviceaccount.com'`.
    * `sourceTags`:
      * **Description**: (*optional, 256 tags max*) A list of tags if using source tags in firewall rules.
      * **Valid values**: List. Any GCP supported tag, e.g. `linux`.
    * `destinationRanges`:
      * **Description**: (*required if `egress`, 256 ranges max*) A list of destination ranges.
      * **Valid values**: List of CIDR formatted IP ranges, e.g. `'0.0.0.0/0'` 
    * `targetServiceAccounts`: 
      * **Description**: (*optional*) A list of service accounts if using source service accounts in firewall rules.
      * **Valid values**: List of service account email addresses, e.g. `'PROJECT@compute.gserviceaccount.com'`.
    * `targetTags`:
      * **Description**: (*optional, 256 tags max*) A list of tags if using target tags in firewall rules.
      * **Valid values**: List. Any GCP supported tag, e.g. `linux`.
  * **Notes**:   
    * You specify either a source or a destination, but not both.  
    Depending on the `direction` of the firewall rules you want to match:  
      * For `ingress` rules, the target parameter specifies the destination VMs for traffic.
      * For `egress` rules, the target parameter specifies the source VMs for traffic.
    * The `source` parameters are only applicable to `ingress` rules, `ingress` rules cannot include `target` parameters.  
    `ingress` rules require that you specify one of the following:
      * `sourceRanges`
      * `sourceServiceAccounts`
      * `sourceTags
      * A combination of `sourceRanges` and `sourceServiceAccounts`
      * A combination of `sourceRanges` and `sourceTags`
    * The `target` parameters are only applicable to `egress` rules, `egress` rules cannot include `source` parameters.  
    The `destinationRanges` is required for `egress` rules.
    

* `verify_policies` (*only for `blacklist` and `whitelist` modes*) TODO
  * **Description**: Policies to verify on firewall rules when scanning.
  * **Content**:  
    * `allowed`:
      * **Description**: (*Repeatable*) Combination of `IPProtocol` and `ports` that describes a permitted connection.
      * `IPProtocol`:
        * **Description**: (*required*) The IP Protocol you wish to verify.
        * **Valid values**: *String*. One of `TCP`, `UDP`, `ICMP`, `ESP`, `AH`, `IPIP`, `SCTP`, or `ALL`.
      * `ports`:
        * **Description**: (*optional*) A list of ports, only applicable for `TCP` and `UDP` protocols.
        * **Valid values**: *List of strings*. Can be single ports `22`, `3389` or a range `0-1024`, or `all` (shortcut for `0-65535`).  
      * **Notes**: Only one of `allowed` or `denied` can be used at the same time.
    * `denied`:
      * **Description**: (*Repeatable*) Combination of `IPProtocol` and `ports` that describes a unauthorized connection.
      * `IPProtocol`:
        * **Description**: (*required*) The IP Protocol we wish to verify.
        * **Valid values**: *String*. One of `TCP`, `UDP`, `ICMP`, `ESP`, `AH`, `IPIP`, `SCTP`, or `ALL`.
      * `ports`:
        * **Description**: (*optional*) A list of ports, only applicable for `TCP` and `UDP` protocols.
        * **Valid values**: *List of strings*. Can be a list of single ports `22`, `3389` or a range `0-1024`, or `all` (shortcut for `0-65535`).  
      * **Notes**: Only one of `allowed` or `denied` can be used at the same time.
    * `sourceRanges`:
      * **Description**: (*optional, 256 ranges max*) A list of source ranges.
      * **Valid values**: List of CIDR formatted IP ranges, e.g. `'0.0.0.0/0'`
    * `sourceTags`:
      * **Description**: (*optional, 256 tags max*) A list of tags if using source tags in firewall rules.
      * **Valid values**: List. Any GCP supported tag, e.g. `linux`.


Sample firewall rules for each mode are available at `samples/scanner/scanners/firewall_rules/`.  
To learn more, see the [Firewalls API Reference](https://cloud.google.com/compute/docs/reference/latest/firewalls)
and the [Firewall rules in GCP](https://cloud.google.com/vpc/docs/firewalls#firewall_rule_components) documentation.

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

## Google Group rules

### Rule definition

```yaml
- name: Allow my company users and gmail users to be in my company groups.
  group_email: my_customer
  mode: whitelist
  conditions:
    - member_email: '@MYDOMAIN.com'
    - member_email: '@gmail.com'
    # GCP Service Accounts
    # https://cloud.google.com/compute/docs/access/service-accounts
    #- member_email: "gserviceaccount.com"
    # Big Query Transfer Service
    #- member_email: "@bqdts.google.baggins"
```

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

## KMS rules

### Rule definition

```yaml
rules:
  - name: sample rule to allow symmetric keys with this configuration
    mode: whitelist
    resource:
      - type: organization
        resource_ids:
          - '*'
    key:
      - rotation_period: 100 #days
        algorithm: 
        - GOOGLE_SYMMETRIC_ENCRYPTION
        protection_level: SOFTWARE
        purpose: 
        - ENCRYPT_DECRYPT
        state:
        - ENABLED
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.
  
* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: String.  One of `blacklist` or `whitelist`.
  * **Note**:
    * `whitelist`: Allow the crypto key configuration defined.
    * `blacklist`: Block the crypto key configuration defined.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: String. Only `organization` is supported.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String, you can use `*` to match for all.

* `key`
  * **Description**: A list of crypto key configuration details to check for.
    * `rotation_period`
      * **Description**: Optional, the maximum number of days in which the key 
      should be rotated.
      * **Valid values**: String, number of days.
      
    * `algorithms`
      * **Description**: Optional, a list of algorithms to whitelist/blacklist.
      * **Valid values**: String.
      * **Example values**: `GOOGLE_SYMMETRIC_ENCRYPTION`, `EC_SIGN_P256_SHA256`
      
    * `protection_level`
      * **Description**: Optional, the protection level to which you want to
      apply the rule.
      * **Valid values**: One of `SOFTWARE` or `HSM`.
      
    * `purpose`
      * **Description**: Optional, a list of purpose to whitelist/blacklist. 
      * **Valid values**: String
      * **Example values**: `ENCRYPT_DECRYPT`, `ASYMMETRIC_SIGN` and 
      `ASYMMETRIC_DECRYPT`.

      
    * `state`
      * **Description**: Optional, a list of states to whitelist/blacklist.
      * **Valid values**: String.
      * **Example values**: `PENDING_GENERATION`, `ENABLED`, `DISABLED`, 
      `DESTROY_SCHEDULED` and `DESTROYED`.

## Kubernetes Engine rules

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

` `values`
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
    
## Kubernetes Engine version rules

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

## Lien rules

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

## Location rules

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

## Retention rules

### Rule definition

```yaml
rules:
  - name: All buckets and bigquery tables in the organization should have a retention policy for 100 to 200 days.
    applies_to:
      - bucket
      - bigquery_table
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
    * **Valid values**: String, Currently only supports `bucket` and `bigquery_table`.
    
* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder`, `project`, `bucket`,
      or `bigquery_table`.

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
    
## Service Account Key rules

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


