---
title: Service Account roles and Required APIs
order: 103
---

# {{ page.title }}

This page lists the IAM roles to be granted and APIs to be enabled in order
to execute the Forseti Terraform module.

---

### **IAM Roles**

For this module to work, you need the following roles enabled on the Service Account:

{% include docs/latest/forseti-terraform-sa-roles.md %}

### **APIs**

For this module to work, you need the following APIs enabled on the Forseti project:

{% include docs/latest/forseti-terraform-setup-apis.md %}
