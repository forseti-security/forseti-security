---
title: Scanner
order: 004
---

# {{ page.title }}

Forseti Scanner scans the inventory data according to the rules (policies) you defined.

You can learn about how to [define custom rules]({% link _docs/latest/configure/scanner/rules.md %}).

## Running Forseti Scanner

Forseti Scanner works on a data model, so before you start using Scanner, you'll select a model to use. 

Instructions on how to [create a model]({% link _docs/latest/use/model.md %}).

To configure which scanners to run, see 
[Configuring Forseti: Configuring Scanner]({% link _docs/latest/configure/scanner/index.md %}).


### Selecting a data model

```bash
$ forseti model use <YOUR_MODEL_NAME>
```

### Running the scanner

```bash
$ forseti scanner run
```

When Scanner finds a rule violation, it outputs the data to a Cloud SQL database.

Scanner can save violations as a CSV and send an email notification or upload it
automatically to a Cloud Storage bucket. 

**Below is an example of scanner violation output**

{% responsive_image path: images/docs/quickstarts/scanner-output.png alt: "sample scanner output" %}

To receive notifications for violations, run the 
[Forseti Notifier]({% link _docs/latest/use/notifier.md %}).

