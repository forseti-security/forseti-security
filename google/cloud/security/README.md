# Forseti Security modules

The Forseti Security modules are developed as modules under `google.cloud.security`.
Each module has its own classes that encapsulate the tool's core functionality.
There are also runner scripts that execute the tool.

## Adding new modules

To add a new module, create it in this directory. Once you have a runner script
that works, create a runner function in the `stubs.py` and plug it into the setup.py
`entry_points['console_scripts']` dictionary.

Re-run `python setup.py install` to install the new console script.
