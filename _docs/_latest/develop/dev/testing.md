---
title: Testing
order: 105
---
# {{ page.title }}

This page describes how to run tests on your Forseti contributions.

## Before you begin

Before you run unit tests, install Forseti by following the
[Developer Setup]({% link _docs/latest/develop/dev/setup.md %}) for
a local installation or the
[Google Cloud Platform (GCP) setup]({% link _docs/latest/configure/general/index.md %})
for a Compute Engine installation. You will need to connect to that
instance to run the unit tests.

---

## Executing tests

Unit tests are in the top-level `tests/` directory. We use
[`unittest`](https://docs.python.org/2/library/unittest.html) from standard Python to run our tests.

Before you run unit tests and pylint checkers, make sure you have
[Docker CE](https://docs.docker.com/install/) installed.


**Run the following commands in the _top-level_ directory of Forseti.**

Install Forseti in a docker image:

  ```bash
  ./install/scripts/docker_setup_forseti.sh
  ```

Start the forseti container:

  ```bash
  ./install/scripts/docker_run_forseti.sh
  ```

Run all the unit tests:

  ```bash
  ./install/scripts/docker_unittest_forseti.sh
  ```

Run pylint checkers:

  ```bash
  ./install/scripts/docker_pystyle_forseti.sh
  ```

### Executing Individual Tests

If you want to execute individual tests:

   ```bash
   docker -l error exec -it build /bin/bash -c "python -m unittest tests.common.util.date_time_test"
   ```

If you want to execute a subset of tests (e.g., all tests in a specific subdirectory):

    ```bash
    docker -l error exec -it build /bin/bash -c "python -m unittest discover -s tests/common -p '*_test.py'"
    ```
