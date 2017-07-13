---
title: Scanner
order: 101
---
# {{ page.title }}

This quickstart describes how to get started with Forseti Scanner. Forseti
Scanner uses a JSON or YAML rules definition file to audit your Google Cloud
Platform (GCP) resources, such as organizations or projects. After running the
audit, Forseti Scanner outputs rule violations to Cloud SQL and optionally
writes it to a bucket in Google Cloud Storage.

Forseti Scanner is different from the Cloud Security Scanner, which does App
Engine vulnerability scanning. Learn more about
[Cloud Security Scanner](https://cloud.google.com/security-scanner/).

## Scanner Rule Engines

Forseti Scanner currently runs a single scanner engine at a time. To see a list of 
available engines, run:

```bash
$ forseti_scanner --list_engines
```

## Running Forseti Scanner

To run Forseti Scanner, follow the process below:

  1. Activate any virtualenv you're using for your Forseti installation,
  if applicable.

  1. Edit the sample `rules.yaml` file in the `samples/` directory to fit your
  environment. Learn more about
  [defining rules for Forseti Scanner]({% link _docs/howto/scanner-rules.md %}).

  1. Run Scanner for your rules file location:

     1. If you're using a rules file stored in Google Cloud Storage, such as
      gs://my-bucket-name/rules/rules.yaml, run the following command:

          ```bash
          $ forseti_scanner --rules "gs://my-bucket-name/rules/rules.yaml"
          ```

     1. If you're using a rules file stored locally, the `RULES_LOCATION` will
      correspond to the local path of that rules file.
      
          ```bash
          $ forseti_scanner --rules RULES_PATH.yaml --input_bucket PROJECT_ID
          ```

  1. By default, Forseti Scanner saves the CSV output to a temporary location.
  To specify an output location, add the following flag to the command
  where OUTPUT_PATH is the location (either on the local filesystem or in GCS)
  where you want to save the CSV

      ```bash
      $ forseti_scanner --rules path/to/rules.yaml \
        --engine_name ENGINE_NAME \
        --output_path OUTPUT_PATH
      ```

If you're developing a new feature or bug fix, you can run Forseti Scanner
using [`./dev_scanner.sh`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/samples/scanner/dev_scanner.sh.sample).
By doing so, you won't have to set the `PYTHONPATH` or other commandline flags
manually.

## What's next

- Read about [configuring Forseti]({% link _docs/howto/configuring-forseti.md %})
- Learn about [defining rules]({% link _docs/howto/scanner-rules.md %}).
