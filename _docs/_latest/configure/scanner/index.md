---
title: Scanner
order: 101
---

# {{ page.title }}

This quickstart describes how to get started with Forseti Scanner. Forseti
Scanner uses a JSON or YAML rules definition file to audit your Google Cloud
Platform (GCP) resources, such as organizations or projects. After running the
audit, Forseti Scanner outputs rule violations to Cloud SQL and optionally
writes it to Cloud Storage bucket.

Forseti Scanner is different from the Cloud Security Scanner, which does App
Engine vulnerability scanning. Learn more about
[Cloud Security Scanner](https://cloud.google.com/security-scanner/).

You can learn how to run the [Forseti Scanner]{% link _docs/latest/use/index.md %}).

## What's next

- Read more about [configuring Scanner]({% link _docs/latest/configure/scanner/index.md %}).
- Learn about the [different scanners]({% link _docs/latest/configure/scanner/descriptions.md %}) available in Forseti.
- Learn about [defining rules]({% link _docs/latest/configure/scanner/rules.md %}).
- Read about how Scanner outputs [policy violations]({% link _docs/latest/configure/scanner/policy-violations.md %}).
- Read more about [the concepts of data model]({% link _docs/latest/concepts/models.md %}).
