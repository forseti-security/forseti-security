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

1. Open `forseti-security/configs/server/forseti_conf_server.yaml`.
1. Navigate to the `scanner` > `scanners` section.
1. Edit the `enabled` property for the appropriate scanners.
   `true` enables the scanner, and `false` disables the scanner.

When you're finished making changes, run the
[configuration reload]({% link _docs/v2.22/use/cli/server.md %})
command to update the configuration of the server.

You can learn how to run the [Forseti Scanner]({% link _docs/v2.22/use/cli/scanner.md %}).

---

## What's next

* Read more about [configuring Scanner]({% link _docs/v2.22/configure/scanner/index.md %}).
* Learn about the [different scanners]({% link _docs/v2.22/configure/scanner/descriptions.md %}) available in Forseti.
* Learn about [defining rules]({% link _docs/v2.22/configure/scanner/rules.md %}).
* Read about how Scanner outputs [policy violations]({% link _docs/v2.22/use/cli/scanner.md %}).
* Read more about [the concepts of data model]({% link _docs/v2.22/concepts/models.md %}).
