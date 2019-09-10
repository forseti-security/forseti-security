---
title: Notifier
order: 104
---

# {{ page.title }}

This page describes how Forseti Notifier is used and run.

Notifier can either run as part of the scheduled cron job's workflow
or manually invoked using the Forseti command-line interface (CLI).

When the cron job runs the Notifier, it sends notifications on the
latest violations from the previous Scanner run.

---

## Running Notifier

Following are the CLI commands you can use with Notifier:

  ```bash
  forseti notifier --help

  forseti notifier run

  # Send the violations by inventory index id.
  forseti notifier run --inventory_index_id <INVENTORY_INDEX_ID>
  
  # Send the violations by scanner index id.
  forseti notifier run --scanner_index_id <SCANNER_INDEX_ID>
  ```

