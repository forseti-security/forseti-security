---
title: Config Validator
order: 007
---

# {{ page.title }}

This page describes how Config Validator works.

---

## **Overview**

The Config Validator Scanner allows you to scan for non-compliant resources in 
your GCP infrastructure. 

### **How It Works**

- Cloud admins write security and governance constraints (as YAML files) once, 
and store them within their company’s dedicated Git repo as a central source of 
truth.
- Forseti ingests policy constraints written in Rego and uses them as a new 
scanner to monitor for violations.
- Terraform Validator reads the same constraints to check for violations before 
provisioning, in order to help prevent misconfigurations from happening.

These constraints are a good way for you to translate your security policies 
into code, and can be configured to meet your granular requirements. And because 
policy constraints are based on Config Validator templates, it’s easy to reuse 
the same code base to implement similar, but distinct constraints.

With this scanner in place, users are now able to define customized policies 
easily without writing a new scanner. Hence, the Forseti Security team does not 
plan to add any new custom scanners or expand the existing custom scanners.

## **What’s next**
- Read more about how to set up the Config Validator Scanner and sync policies 
with the Forseti Server [here]({% link _docs/latest/configure/config-validator/index.md %}).
- Read more about how to write your own constraint templates [here](https://github.com/forseti-security/policy-library/blob/master/docs/constraint_template_authoring.md).
- Read more about Terraform Validator [here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#how-to-use-terraform-validator).
