---
title: Notifier
order: 005
---

# {{ page.title }}

This page describes how the Notifier is used and run.

Notifier can either be run as part of the scheduled cron job's workflow
or manually invoked using the Forseti CLI.

When the cron job runs the Notifier, it sends notifications on the
latest violations from the previous scanner run.

### CLI Usage

  ```bash
  $ forseti notifier --help
  
  $ forseti notifier run

  # Send the violations by inventory index id.
  $ forseti notifier run --inventory_index_id <inventory index id>
  ```
  