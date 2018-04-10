---
title: Scanner
order: 101
---
# {{ page.title }}

This page describes how to get started with Forseti Scanner. Forseti
Scanner uses a JSON or YAML rules definition file to audit your Google Cloud
Platform (GCP) resources, such as organizations or projects. After running the
audit, Forseti Scanner outputs rule violations to Cloud SQL and optionally
writes it to a bucket in Google Cloud Storage.

Forseti Scanner is different from the Cloud Security Scanner, which does App
Engine vulnerability scanning. Learn more about
[Cloud Security Scanner](https://cloud.google.com/security-scanner/).

## Scanners

Forseti Scanner can run multiple scanners at a time. To configure which scanners
to run, see [Configuring Forseti: Configuring Scanner]({% link _docs/latest/configure/configuring-forseti.md %}#configuring-scanner).

## Running Forseti Scanner

To run Forseti Scanner, follow the process below:

  1. Activate any virtualenv you're using for your Forseti installation,
     if applicable (e.g. if you're running in a dev environment).
     
  1. Run the [inventory data import]({% link _docs/latest/configure/inventory/index.md %}#executing-the-inventory-loader) 
     first, to make sure the data for scanning is available and up-to-date.

  1. Run the scanners:

  ```bash
  $ forseti_scanner --forseti_config <path to forseti_conf.yaml>
  ```

If you're developing a new feature or bug fix, you can run Forseti Scanner
using [`./dev_scanner.sh`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/samples/scanner/dev_scanner.sh.sample).
By doing so, you won't have to set the `PYTHONPATH` or other commandline flags
manually.

## What's next

- Read more about [configuring Scanner]({% link _docs/latest/configure/configuring-forseti.md %}#configuring-scanner).
- Learn about the [different scanners]({% link _docs/latest/configure/scanner/descriptions.md %}) available in Forseti.
- Learn about [defining rules]({% link _docs/latest/configure/scanner/rules.md %}).
- Read about how Scanner outputs [policy violations]({% link _docs/latest/configure/scanner/policy-violations.md %}).
