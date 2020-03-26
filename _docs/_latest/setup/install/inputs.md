---
title: Terraform input variables
order: 102
---

# {{ page.title }}

This page lists the sample variables you can use to customize your Forseti 
installation.

---

### **Terraform input variables**

The following variables have been listed as a sample to help you identify and 
set any customized values. There may be other variables with customized values 
that will need to be set.

View the list of inputs [here](https://github.com/forseti-security/terraform-google-forseti#inputs) 
to see all of the available options and default values.

{: .table .table-striped}
| Name | Description | Type | Default |
|---|---|:---:|:---:|
| composite\_root\_resources | A list of root resources that Forseti will monitor. This supersedes the root_resource_id when set. | list(string) | `<list>` |
| cscc\_source\_id | Source ID for CSCC Beta API | string | `""` | 
| cscc\_violations\_enabled | Notify for CSCC violations | bool | `"false"` |
| excluded\_resources | A list of resources to exclude during the inventory phase. | list(string) | `<list>` |
| forseti\_email\_recipient | Email address that receives Forseti notifications | string | `""` |
| forseti\_email\_sender | Email address that sends the Forseti notifications | string | `""` |
| gsuite\_admin\_email | G-Suite administrator email address to manage your Forseti installation | string | `""` |
| inventory\_email\_summary\_enabled | Email summary for inventory enabled | bool | `"false"` |
| inventory\_gcs\_summary\_enabled | GCS summary for inventory enabled | bool | `"true"` |
| sendgrid\_api\_key | Sendgrid.com API key to enable email notifications | string | `""` |
| violations\_slack\_webhook | Slack webhook for any violation. Will apply to all scanner violation notifiers. | string | `""` |
