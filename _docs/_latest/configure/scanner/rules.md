---
title: Defining Rules
order: 301
---

# {{ page.title }}

This page describes the Forseti scanners that are available, how they work, and
why they're important. You can
[configure Scanner]({% link _docs/latest/configure/scanner/index.md %}) to execute
multiple scanners in the same run.

---

## Defining custom rules

You can find some starter rules in the
[rules](https://github.com/GoogleCloudPlatform/forseti-security/tree/stable/rules)
directory. When you make changes to the rule files, upload them to your
Forseti bucket under `forseti-server-xxxx/rules/` or copy them to the `rules_path`
listed in `forseti_server_conf.yaml`.

