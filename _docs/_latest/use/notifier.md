---
title: Notifier
order: 003
---
# {{ page.title }}

This page describes how the Notifier is used and run.

Notifier can either be run as part of the scheduled cron job's workflow
or manually invoked using the Forseti CLI.

When the cron job runs the Notifier, it sends notifications on the
latest violations from the previous scanner run.

See the [CLI usage guide]({% link _docs/latest/use/cli.md %}), for how
to invoke Forseti on-demand.
