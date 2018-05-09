---
title: Command line interface (CLI)
order: 001
---

# {{ page.title }}

TODO

## Notifier

  ```bash
  $ forseti notifier --help
  
  # Send the violations from the last successful scanner run.
  $ forseti notifier run

  # Send the violations by inventory index id.
  $ forseti notifier run --inventory_index_id <inventory index id>

  # Send the violations by scanner index id.
  $ forseti notifier run --scanner_index_id <scanner index id>
  ```
