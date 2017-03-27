# Tests
You can find the unit tests in the top-level `tests/` directory. They are built on the google-apputils [basetest](https://github.com/google/google-apputils).

To execute them, run:

```sh
$ python setup.py google_test --test-dir tests/
```

If you would like to execute the tests just for a particular module:

```sh
$ python setup.py google_test --test-dir tests/<MODULE_NAME>
```
