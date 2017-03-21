# Installing locally
* [Installing](#installing)
* [Execution](#execution)
* [Tests](#tests)
* [Forseti Security modules](#forseti-security-modules)

## Prerequisites
See the [prerequisistes](/docs/PREREQUISITES-LOCALLY.md)for installing locally.

## Create a virtualenv and activate it, e.g.:
```sh
$ mkvirtualenv forseti-security
$ workon forseti-security
```

## Get the source code
Clone the repo, if you haven't already done so:

## Run the python setup
Navigate to your cloned repo, then run:

```sh
$ python setup.py install
```

## Execution
You should now be able to run the following commandline tools. To see the flag options for each, use
the `--helpshort` or `--helpfull` flags.

 - `forseti_inventory` ([README](/google/cloud/security/inventory/README.md))
 - `forseti_scanner` ([README](/google/cloud/security/scanner/README.md))
 - `forseti_enforcer` ([README](/google/cloud/security/enforcer/README.md))

## Tests
There are unit tests in the `tests/` directory. To execute them, run:

```sh
$ python setup.py google_test --test-dir <test dir>
```

## Forseti Security modules
The Forseti Security modules are developed as modules under `google.cloud.security`.
Each module has its own classes that encapsulate the tool's core functionality.
There are also runner scripts that execute the tool.

## Adding new modules
To add a new module, create it in this directory. Once you have a runner script
that works, create a runner function in the `stubs.py` and plug it into the setup.py
`entry_points['console_scripts']` dictionary.

Re-run `python setup.py install` to install the new console script.
