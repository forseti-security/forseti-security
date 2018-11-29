---
title: Google Groups Rules
order: 350 
---

# {{ page.title }}

## Description

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
