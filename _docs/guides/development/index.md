---
title: Development
order: 001
hide:
  left_sidebar: true
---
# {{ page.title }}

## Contributing

We welcome your contributions! Before you start, please review our
[contributing guidelines](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/.github/CONTRIBUTING.md).

## Testing

This page describes how to run tests on your Forseti contributions.

### Unit tests

You can find unit tests in the top-level `tests/` directory. We use [`unittest`](https://docs.python.org/2/library/unittest.html)
from standard Python to run our tests.

Before you run unit tests, please build the protos if you haven't already.
Some of the unit tests will fail if they cannot find the required protos.

**The following commands should be run in the _top-level_ directory of Forseti.**

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
