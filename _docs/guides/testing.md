---
title: Testing
order: 003
---
# {{ page.title }}

This page describes how to run tests on your Forseti contributions.

## Executing tests

You can find unit tests in the top-level `tests/` directory. We use [`unittest`](https://docs.python.org/2/library/unittest.html)
from standard Python to run our tests.

Before you run unit tests, build the protos if you haven't already.
Some of the unit tests will fail if they can't find the required protos.

**Run the following commands in the _top-level_ directory of Forseti.**

  ```bash
  python build_protos.py --clean
  ```

To execute all the unit tests:

  ```bash
  python -m unittest discover -s . -p "*_test*"
  ```

To execute the tests just for a particular file pattern:

  ```bash
  python -m unittest discover -s . -p "*some_feature_test*"
  ```
