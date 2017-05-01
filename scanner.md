# Scanner

The Forseti Scanner takes a rules definition file (either json or
yaml) as input and uses it to audit your Google Cloud Platform resources (e.g.
organizations, projects). After running the audit, it outputs a csv file and
optionally writes it to a bucket in Google Cloud Storage.

If you are interested in vulnerability scanning please see [Cloud Security Scanner](https://cloud.google.com/security-scanner/).

## Running the scanner

* Activate the virtualenv (if applicable) of your Forseti installation.

* A sample rules file can be found in the samples/ directory. You should edit
  this to fit your environment.

* To see all the available commandline flags for the scanner, run:

  ```sh
  $ forseti_scanner --helpfull
  ```

  To run the scanner with a local rules file:

  ```sh
  $ forseti_scanner --rules path/to/rules.yaml
  ```

  To run the scanner with a rules file stored in GCS, e.g.
  `gs://my-project-id/rules/rules.yaml`:

  ```sh
  $ forseti_scanner --rules "rules/rules.yaml" --input_bucket my-project-id
  ```

* By default, the scanner will save the csv output to a temporary location. Specify an output path (it can also be a GCS bucket) in order to save the csv there.

  To specify the output location for the violations:

  ```sh
  $ forseti_scanner --rules "rules/rules.yaml" --output_path path/for/output/
  ```

* If you are developing a new feature or bug fix, you can also use the convenience [dev_scanner.sh script](/scripts) to run scanner so you don't have to set PYTHONPATH and other commandline flags manually.

```sh
$ cd path/to/forseti-security
$ scripts/dev_scanner.sh
```

## Defining rules

Refer to the [documentation](rules.md) on the rules schema.
