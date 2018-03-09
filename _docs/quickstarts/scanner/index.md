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

## Running Forseti Scanner

Forseti Scanner works on a data model, so before you start using Scanner, you'll select a model to use. 
For information about how to create a model, see Testing Models.

To configure which scanners to run, see 
[Configuring Forseti: Configuring Scanner]({% link _docs/howto/configure/configuring-forseti.md %}#configuring-scanner).


#### Selecting a data model

```bash
$ forseti model use <YOUR_MODEL_NAME>
```

#### Running the scanner

```bash
$ forseti scanner run
```

Scanner produces violations and stores them in the violation table in the database. 
To receive notifications for violations, run the 
[Forseti Notifier]({% link _docs/configure/notifier/index.md %}).

## What's next

- Read more about [configuring Scanner]({% link _docs/configure/scanner/index.md %}).
- Learn about the [different scanners]({% link _docs/quickstarts/scanner/descriptions.md %}) available in Forseti.
- Learn about [defining rules]({% link _docs/quickstarts/scanner/rules.md %}).
- Read about how Scanner outputs [policy violations]({% link _docs/quickstarts/scanner/policy-violations.md %}).
- Read more about [the concepts of data model]({% link _docs/concepts/models.md %}).
