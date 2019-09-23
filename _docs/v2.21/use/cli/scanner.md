---
title: Scanner
order: 103
---

# {{ page.title }}

Forseti Scanner scans Inventory data according to the rules (policies) you defined.

For more information about rules, see how to
[define custom rules]({% link _docs/v2.21/configure/scanner/rules.md %}).

---

## Running Forseti Scanner

Forseti Scanner works on a data model. Before you start using Scanner, you'll
select the model you want to use.

If you haven't created a model yet, see [create a model]({% link _docs/v2.21/use/cli/model.md %}).

To configure which scanners to run, see
[Configuring Forseti: Configuring Scanner]({% link _docs/v2.21/configure/scanner/index.md %}).


### Selecting a data model

```bash
forseti model use <YOUR_MODEL_NAME>
```

### Running the scanner

To run scanners (excluding external project access scanner):
```bash
forseti scanner run
```

The external project access scanner is not part of the regular running scanners, as it may take hours to run. 
Therefore, we now make this scanner accessible manually through the CLI. <br />
**Note:** You will need to create an inventory and model if it is not already
created. 
```bash
MODEL_ID=$(/bin/date -u +%Y%m%dT%H%M%S)
forseti inventory create --import_as ${MODEL_ID}
forseti model use ${MODEL_ID}
forseti scanner run --scanner external_project_access_scanner
forseti notifier run --scanner_index_id <SCANNER_INDEX_ID>
```

When Scanner finds a rule violation, it outputs the data to a Cloud SQL database.

## Sample scanner violation

### Firewall rule violation

{: .table .table-striped}
| resource_id | resource_type | full_name | rule_index | rule_name | violation_type | violation_data |
|---|---|---|---|---|---|---|
| my-project-1 | firewall_rule | organization/1234567890/project/my-project-1/firewall/494704901029517064/ | 1 | disallow_all_ports | FIREWALL_BLACKLIST_VIOLATION | {u'policy_names': [u'gke-staging-9696e33a-all'], u'recommended_actions': {u'DELETE_FIREWALL_RULES': [u'gke-staging-9696e33a-all']}} |
| my-project-2 | firewall_rule | organization/1234567890/project/my-project-2/firewall/494704901029517064/ | 1 | disallow_all_ports | FIREWALL_BLACKLIST_VIOLATION | {u'policy_names': [u'gke-canary-west-69bb2963-all'], u'recommended_actions': {u'DELETE_FIREWALL_RULES': [u'gke-canary-west-69bb2963-all']}} |

### BigQuery violation

{: .table .table-striped}
| resource_id | resource_type | full_name | rule_index | rule_name | violation_type | violation_data |
|--------------|---|---|---|---|---|---|
| my-project-1:testdataset1 | bigquery_dataset | organization/1234567890/project/my-project-1/dataset/my-project-1:testdataset1/dataset_policy/dataset/my-project-1:testdataset1/ | 0 | Search for public datasets | BIGQUERY_VIOLATION | {u'access_user_by_email': u'', u'access_special_group': u'allAuthenticatedUsers', u'access_domain': u'', u'access_group_by_email': u'', u'role': u'READER', u'full_name': u'organization/1234567890/project/my-project-1/dataset/my-project-1:testdataset1/dataset_policy/dataset/my-project-1:testdataset1/', u'dataset_id': u'my-project-1:testdataset1', u'view': {}} |
| my-project-1:testdataset1 | bigquery_dataset | organization/1234567890/project/my-project-1/dataset/my-project-1:testdataset1/dataset_policy/dataset/my-project-1:testdataset1/ | 0 | Search for datasets accessible by users with gmail.com addresses | BIGQUERY_VIOLATION | {u'access_user_by_email': u'my_test_acc_1@gmail.com', u'access_special_group': u'allAuthenticatedUsers', u'access_domain': u'', u'access_group_by_email': u'', u'role': u'READER', u'full_name': u'organization/1234567890/project/my-project-1/dataset/my-project-1:testdataset1/dataset_policy/dataset/my-project-1:testdataset1/', u'dataset_id': u'my-project-1:testdataset1', u'view': {}} |

### Cloud SQL violation

{: .table .table-striped}
| resource_id | resource_type | full_name | rule_index | rule_name | violation_type | violation_data |
|---|---|---|---|---|---|---|
| my-project-1 | cloudsql | organization/1234567890/project/my-project-1/cloudsqlinstance/readme1/  | 0  |  publicly exposed instances | CLOUD_SQL_VIOLATION | {u'instance_name': u'readme1', u'require_ssl': False, u'project_id': u'readme1', u'authorized_networks': [u'0.0.0.0/0'], u'full_name': u'organization/1234567890/project/my-project-1/cloudsqlinstance/readme1/'} |

## What's next

* Learn how to [use Notifier]({% link _docs/v2.21/use/cli/notifier.md %}) to send notifications on the
violations found by Scanner.
