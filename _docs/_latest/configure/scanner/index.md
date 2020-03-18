---
title: Scanner
order: 300
---

# {{ page.title }}

This quickstart describes how to get started with Forseti Scanner. Forseti
Scanner uses a JSON or YAML rules definition file to audit your Google Cloud
Platform (GCP) resources, such as organizations or projects. After running the
audit, Forseti Scanner outputs rule violations to Cloud SQL and optionally
writes it to Cloud Storage bucket.

## Configuring Scanner

Forseti Scanner runs in batch mode, executing each scanner serially
for each run. To modify the scanner settings:

1. View the list of inputs [here](https://github.com/forseti-security/terraform-google-forseti#inputs) to see all of the available options and default values.
1. Set the input variable for the scanner whose settings you want to modify to
`true` or `false` in your `main.tf`, where `true` enables the scanner, and 
`false` disables the scanner. For example, setting `config_validator_enabled` to 
`true` enables Config Validator Scanner.

When you're finished making changes:
- Run command `terraform plan` to see the infrastructure plan. 
- Run command `terraform apply` to apply the infrastructure build.

You can learn how to run the [Forseti Scanner]({% link _docs/latest/use/cli/scanner.md %}).

---

## What's next

* Read more about [configuring Scanner]({% link _docs/latest/configure/scanner/index.md %}).
* Learn about the [different scanners]({% link _docs/latest/configure/scanner/descriptions.md %}) available in Forseti.
* Learn about [defining rules]({% link _docs/latest/configure/scanner/rules.md %}).
* Read about how Scanner outputs [policy violations]({% link _docs/latest/use/cli/scanner.md %}).
* Read more about [the concepts of data model]({% link _docs/latest/concepts/models.md %}).
